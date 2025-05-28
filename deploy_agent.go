package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v2"
)

// Config 配置结构体
type Config struct {
	Port          int      `yaml:"port"`
	IPWhitelist   []string `yaml:"ip_whitelist"`
	Workspace     string   `yaml:"workspace"`
	MaxUploadSize int64    `yaml:"max_upload_size"` // 最大上传大小(MB)
	APIKey        string   `yaml:"api_key"`         // API Key用于认证
	RateLimit     int      `yaml:"rate_limit"`      // 每分钟允许的请求数
}

var (
	config     Config
	configOnce sync.Once
	mu         sync.Mutex // 保护文件操作

	// IP速率限制器
	ipRateLimiters = make(map[string]*rate.Limiter)
	ipRateMutex    sync.Mutex

	// 优雅关闭信号
	quit = make(chan os.Signal, 1)
)

func main() {
	// 从命令行参数获取配置文件路径
	if len(os.Args) < 2 {
		log.Fatal("请指定配置文件路径: ./program config.yml")
	}
	configFile := os.Args[1]

	// 加载配置文件
	loadConfig(configFile)

	// 验证配置
	if err := validateConfig(); err != nil {
		log.Fatalf("配置验证失败: %v", err)
	}

	// 确保工作空间存在
	if err := os.MkdirAll(config.Workspace, 0755); err != nil {
		log.Fatalf("无法创建工作空间目录: %v", err)
	}

	// 设置路由
	mux := http.NewServeMux()
	mux.HandleFunc("/deploy", uploadHandler)

	// 创建服务器
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", "0.0.0.0", config.Port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	log.Printf("服务器启动成功，监听端口: %d", config.Port)
	// 启动优雅关闭
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("服务器错误: %v", err)
		}
	}()

	// 等待中断信号以优雅地关闭服务器
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("正在关闭服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("服务器强制关闭: %v", err)
	}

	log.Println("服务器已关闭")
}

// 加载配置文件
func loadConfig(filename string) {
	configOnce.Do(func() {
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatalf("无法读取配置文件: %v", err)
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			log.Fatalf("解析配置文件失败: %v", err)
		}

		// 验证工作空间路径
		config.Workspace, err = filepath.Abs(config.Workspace)
		if err != nil {
			log.Fatalf("无效的工作空间路径: %v", err)
		}

		// 验证API Key
		if config.APIKey == "" {
			log.Fatal("配置文件中必须指定API Key")
		}

		// 验证速率限制
		if config.RateLimit <= 0 {
			config.RateLimit = 60 // 默认每分钟60次请求
			log.Printf("未设置速率限制，使用默认值: %d请求/分钟", config.RateLimit)
		}
		log.Printf(" *** config info *** ")
		log.Printf("->  workspace: %v", config.Workspace)
		log.Printf("->  rateLimit: %d ", config.RateLimit)
		log.Printf("->  ipWhitelist: %+v", config.IPWhitelist)
		log.Printf("->  maxUploadSize: %d MB", config.MaxUploadSize)
		log.Printf("->  api key: %s", maskAPIKey(config.APIKey))
		log.Printf(" *** config loaded ***")
	})
}

// 验证配置
func validateConfig() error {
	if config.Port <= 0 || config.Port > 65535 {
		return errors.New("端口必须在1-65535之间")
	}

	if config.MaxUploadSize <= 0 {
		config.MaxUploadSize = 100 // 默认100MB
		log.Printf("未设置最大上传大小，使用默认值: %dMB", config.MaxUploadSize)
	}

	// 验证IP白名单
	for _, ip := range config.IPWhitelist {
		if net.ParseIP(ip) == nil {
			// 检查是否是IP:port格式
			if _, _, err := net.SplitHostPort(ip); err != nil {
				return fmt.Errorf("无效的IP白名单条目: %s", ip)
			}
		}
	}

	if config.APIKey == "" {
		return errors.New("API Key不能为空")
	}

	return nil
}

// 上传处理函数
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// 使用defer确保在panic时也能执行清理
	defer func() {
		if err := recover(); err != nil {
			log.Printf("处理上传时发生panic: %v", err)
			httpError(w, http.StatusInternalServerError, "服务器内部错误")
		}
	}()

	// 检查API Key认证
	if !isAPIKeyValid(r) {
		httpError(w, http.StatusUnauthorized, "无效的API Key")
		return
	}

	// 检查IP白名单
	if !isIPAllowed(r.RemoteAddr) {
		httpError(w, http.StatusForbidden, "IP不在白名单内")
		return
	}

	// 检查速率限制
	if !checkRateLimit(r.RemoteAddr) {
		httpError(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
		return
	}

	// 检查请求方法
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "只支持POST方法")
		return
	}

	// 检查Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		httpError(w, http.StatusBadRequest, "缺少Content-Type头部")
		return
	}

	// 处理multipart/form-data上传
	if strings.HasPrefix(contentType, "multipart/form-data") {
		handleMultipartUpload(w, r)
		return
	}

	httpError(w, http.StatusUnsupportedMediaType, "不支持的Content-Type")
}

// 检查API Key是否有效
func isAPIKeyValid(r *http.Request) bool {
	apiKey := r.Header.Get("X-API-Key")
	return apiKey == config.APIKey
}

// 检查IP是否在白名单内
func isIPAllowed(ip string) bool {
	log.Println("checking ip: ", ip)
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		host = ip
	}

	for _, allowedIP := range config.IPWhitelist {
		if allowedIP == host {
			return true
		}
		// 检查是否是IP:port格式
		if ipWithPort, _, err := net.SplitHostPort(allowedIP); err == nil {
			if ipWithPort == host {
				return true
			}
		}
	}

	return false
}

// 检查IP速率限制
func checkRateLimit(ip string) bool {
	ipRateMutex.Lock()
	defer ipRateMutex.Unlock()

	limiter, exists := ipRateLimiters[ip]
	if !exists {
		// 创建新的速率限制器，每分钟config.RateLimit次请求
		limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(config.RateLimit)), 1)
		ipRateLimiters[ip] = limiter
	}

	return limiter.Allow()
}

// 处理multipart/form-data上传
func handleMultipartUpload(w http.ResponseWriter, r *http.Request) {
	// 解析multipart表单，限制大小
	err := r.ParseMultipartForm(config.MaxUploadSize * 1024 * 1024)
	if err != nil {
		if err.Error() == "request too large" {
			httpError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("上传文件过大，最大允许 %dMB", config.MaxUploadSize))
		} else {
			httpError(w, http.StatusBadRequest, "解析multipart表单失败")
		}
		return
	}

	// 获取目标路径
	targetPath := r.FormValue("targetPath")
	if targetPath == "" {
		httpError(w, http.StatusBadRequest, "目标路径不能为空")
		return
	}

	// 验证目标路径
	targetPath = filepath.Clean(targetPath)
	fullPath := filepath.Join(config.Workspace, targetPath)

	// 确保目标路径在工作空间内
	if !strings.HasPrefix(fullPath, config.Workspace) {
		httpError(w, http.StatusBadRequest, "目标路径超出工作空间范围")
		return
	}

	// 确保目标路径的父目录存在
	parentDir := filepath.Dir(fullPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Sprintf("无法创建目标路径: %v", err))
		return
	}

	// 处理每个文件
	formFiles := r.MultipartForm.File
	if len(formFiles) == 0 {
		httpError(w, http.StatusBadRequest, "没有找到文件")
		return
	}

	for _, fileHeaders := range formFiles {
		for _, fileHeader := range fileHeaders {
			// 打开文件
			file, err := fileHeader.Open()
			if err != nil {
				httpError(w, http.StatusInternalServerError, fmt.Sprintf("无法打开文件: %v", err))
				return
			}
			defer file.Close() // 确保文件句柄关闭
			// 检查文件是否存在，如果存在则备份
			if _, err := os.Stat(fullPath); err == nil {
				backupPath := getBackupPath(fullPath)
				if err := os.Rename(fullPath, backupPath); err != nil {
					httpError(w, http.StatusInternalServerError, fmt.Sprintf("无法备份现有文件: %v", err))
					return
				}
				log.Printf("文件已存在，已备份到: %s", backupPath)
			}

			// 创建目标文件
			outFile, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				httpError(w, http.StatusInternalServerError, fmt.Sprintf("无法创建目标文件: %v", err))
				return
			}
			defer outFile.Close() // 确保文件句柄关闭

			// 复制文件内容
			if _, err := io.Copy(outFile, file); err != nil {
				httpError(w, http.StatusInternalServerError, fmt.Sprintf("无法写入文件: %v", err))
				return
			}
			isAutoUnzip := r.FormValue("isAutoUnzip")
			unzipPath := r.FormValue("unzipPath")
			unzipFullPath := filepath.Join(config.Workspace, unzipPath)
			log.Printf("unzipFullPath %s", unzipFullPath)
			// 检查是否需要解压
			if strings.HasSuffix(fileHeader.Filename, ".zip") && isAutoUnzip == "true" && unzipPath != "" {

				if !strings.HasPrefix(unzipFullPath, config.Workspace) {
					httpError(w, http.StatusBadRequest, "解压目标路径超出工作空间范围")
					return
				}
				if _, err := os.Stat(unzipFullPath); err == nil {
					backupPath := getBackupPath(unzipFullPath)
					if err := os.Rename(unzipFullPath, backupPath); err != nil {
						httpError(w, http.StatusInternalServerError, fmt.Sprintf("无法备份解压目标文件: %v", err))
						return
					}
					log.Printf("解压目标文件已存在，已备份到: %s", backupPath)
				}

				// 解压zip文件
				if err := UnzipSafe(fullPath, unzipFullPath); err != nil {
					httpError(w, http.StatusInternalServerError, fmt.Sprintf("无法解压zip文件: %v", err))
					return
				}
				log.Printf("已解压zip文件到 %s", filepath.Dir(fullPath))
			}

			log.Printf("文件 %s 上传成功到 %s", fileHeader.Filename, fullPath)
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("文件上传成功"))
}

// 获取备份路径
func getBackupPath(originalPath string) string {
	dir := filepath.Dir(originalPath)
	filename := filepath.Base(originalPath)
	ext := filepath.Ext(filename)
	name := strings.TrimSuffix(filename, ext)

	// 获取当前时间戳
	timestamp := time.Now().Format("20060102150405")

	// 构建备份文件名
	backupFilename := fmt.Sprintf("%s_%s%s", name, timestamp, ext)
	return filepath.Join(dir, backupFilename)
}

// 错误响应辅助函数
func httpError(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 6 {
		return "​**​*" // 如果API Key太短，全部替换
	}
	return apiKey[:3] + "​**​*" + apiKey[len(apiKey)-3:]
}

func UnzipSafe(zipFilePath, destDir string) error {
	r, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	for _, f := range r.File {
		// 防止路径遍历攻击
		rcPath := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(rcPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", rcPath)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(rcPath, f.Mode()); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(rcPath), 0755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		outFile, err := os.OpenFile(rcPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			outFile.Close()
			rc.Close()
			return err
		}

		outFile.Close()
		rc.Close()
	}

	return nil
}
