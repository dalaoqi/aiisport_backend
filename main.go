package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	supa "github.com/nedpals/supabase-go"
)

var (
	SupabaseURL     string
	SupabaseAPIKey  string
	Port            string
	StorageEndpoint = "/storage/v1/object"
)

const (
	SupabaseVideosBucket     = "videos"
	SupabaseThumbnailsBucket = "thumbnails"
)

func init() {
	// 讀取 .env 檔案
	if err := godotenv.Load(); err != nil {
		log.Println("未找到 .env 檔案，將嘗試使用系統環境變數")
	}

	// 從環境變數中讀取必要設定
	SupabaseURL = os.Getenv("SUPABASE_URL")
	SupabaseAPIKey = os.Getenv("SUPABASE_API_KEY")
	Port = os.Getenv("PORT")

	// 檢查必要環境變數是否存在
	requiredEnv := []string{"SUPABASE_BUCKET", "SUPABASE_URL", "SUPABASE_API_KEY", "PORT"}
	for _, env := range requiredEnv {
		if os.Getenv(env) == "" {
			log.Fatalf("環境變數 %s 未設定", env)
		}
	}
}

// 上傳影片並生成縮圖
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// 加入 CORS 標頭
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// 處理預檢請求
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	err := r.ParseMultipartForm(100 << 20) // 限制上傳檔案大小 50 MB
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// 取得原始檔名並生成 Hash
	originalFileName := filepath.Base(handler.Filename)
	hashedFileName := generateHashedFileName(originalFileName)
	videoPath := fmt.Sprintf("uploads/%s", hashedFileName)

	// 儲存影片至本地
	os.MkdirAll("uploads", os.ModePerm)
	outFile, err := os.Create(videoPath)
	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, file); err != nil {
		http.Error(w, "Error writing the file", http.StatusInternalServerError)
		return
	}

	// 使用 FFmpeg 生成縮圖
	thumbnailPath := strings.Replace(videoPath, filepath.Ext(videoPath), ".jpg", 1)
	cmd := exec.Command("ffmpeg", "-i", videoPath, "-ss", "00:00:02", "-vframes", "1", "-q:v", "2", thumbnailPath)
	if err := cmd.Run(); err != nil {
		http.Error(w, "Error generating thumbnail", http.StatusInternalServerError)
		return
	}

	// 上傳影片到 Supabase
	uploadToSupabase(SupabaseVideosBucket, videoPath, hashedFileName, handler.Header.Get("Content-Type"))

	// 上傳縮圖到 Supabase
	thumbnailName := strings.Replace(hashedFileName, filepath.Ext(hashedFileName), ".jpg", 1)
	uploadToSupabase(SupabaseThumbnailsBucket, thumbnailPath, thumbnailName, "image/jpeg")

	// 構建 Supabase 中的 video_path 和 thumbnail_path
	videoURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseVideosBucket, hashedFileName)
	thumbnailURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseThumbnailsBucket, thumbnailName)

	// 存 Name, video_path 和 thumbnail_path 到 Supabase 的 video 資料表
	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	// 準備要寫入的資料
	videoRecord := map[string]interface{}{
		"name":           originalFileName,
		"video_path":     videoURL,
		"thumbnail_path": thumbnailURL,
	}

	// 將記錄寫入資料庫
	var result []map[string]interface{}
	err = supabase.DB.From("video").Insert(videoRecord).Execute(&result)
	if err != nil {
		http.Error(w, "Error inserting record to database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("File and thumbnail uploaded successfully: %s", hashedFileName)))
}

// 根據檔名和當前時間生成 Hash
func generateHashedFileName(fileName string) string {
	currentTime := fmt.Sprintf("%d", time.Now().UnixNano())
	hashInput := fileName + currentTime
	hash := sha256.New()
	hash.Write([]byte(hashInput))
	hashedFileName := fmt.Sprintf("%x%s", hash.Sum(nil), filepath.Ext(fileName))
	return strings.ToLower(hashedFileName)
}

// 上傳檔案到 Supabase Storage
func uploadToSupabase(bucket, filePath, fileName, contentType string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return
	}
	defer file.Close()

	buffer := bytes.NewBuffer(nil)
	if _, err := io.Copy(buffer, file); err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}

	uploadURL := fmt.Sprintf("%s%s/%s/%s", SupabaseURL, StorageEndpoint, bucket, fileName)

	req, err := http.NewRequest("POST", uploadURL, buffer)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+SupabaseAPIKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-upsert", "true") // 若檔名重複則覆蓋

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error uploading to Supabase: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Error response from Supabase: %s", string(body))
	}
}

type thumbnailResponse struct {
	Thumbnails []thumbnailData `json:"thumbnails"`
}

type thumbnailData struct {
	ThumbnailURL string `json:"thumbnailURL"`
	VideoURL     string `json:"videoURL"`
	VideoName    string `json:"videoName"`
}

func listThumbnailsHandler(w http.ResponseWriter, r *http.Request) {
	// 加入 CORS 標頭
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// 處理預檢請求
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	// 取得所有檔案
	files := supabase.Storage.From("thumbnails").List("", supa.FileSearchOptions{})

	var thumbnails []thumbnailData
	thumbnails = make([]thumbnailData, 0)
	for _, file := range files {
		// 若為縮圖 (以 .jpg 結尾)
		if strings.HasSuffix(file.Name, ".jpg") {
			// 獲取對應的影片 URL（假設影片名稱與縮圖名稱相同，但副檔名不同）
			videoName := strings.Replace(file.Name, ".jpg", ".mov", 1)
			videoSignedUrlResp := supabase.Storage.From(SupabaseVideosBucket).CreateSignedUrl(videoName, 86400)
			videoURL := videoSignedUrlResp.SignedUrl

			// 獲取縮圖 URL
			thumbnailSignedUrlResp := supabase.Storage.From(SupabaseThumbnailsBucket).CreateSignedUrl(file.Name, 86400)
			thumbnailURL := thumbnailSignedUrlResp.SignedUrl

			// 將縮圖與影片 URL 加入陣列
			thumbnails = append(thumbnails, thumbnailData{
				ThumbnailURL: thumbnailURL,
				VideoURL:     videoURL,
				VideoName:    videoName,
			})
		}
	}

	// 回傳 JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := thumbnailResponse{Thumbnails: thumbnails}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

// 刪除影片和縮圖
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	// 加入 CORS 標頭
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// 處理預檢請求
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// 解析 URL 參數
	vars := mux.Vars(r)
	videoName := vars["videoName"]
	// 刪除影片檔案
	err := deleteFromSupabase(SupabaseVideosBucket, videoName)
	if err != nil {
		http.Error(w, "Error deleting video", http.StatusInternalServerError)
		return
	}

	// 刪除縮圖檔案（假設縮圖與影片檔案有相同名稱，但副檔名為 .jpg）
	thumbnailName := strings.Replace(videoName, ".mov", ".jpg", 1)
	err = deleteFromSupabase(SupabaseThumbnailsBucket, thumbnailName)
	if err != nil {
		http.Error(w, "Error deleting thumbnail", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Video and thumbnail deleted successfully: %s", videoName)))
}

// 從 Supabase Storage 刪除檔案
func deleteFromSupabase(bucket, fileName string) error {
	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	// 刪除檔案
	resp := supabase.Storage.From(bucket).Remove([]string{fileName})
	if resp.Key != "" {
		return fmt.Errorf("error deleting file: %s", resp.Message)
	}
	return nil
}

func logoHandler(w http.ResponseWriter, r *http.Request) {
	// 設定檔案路徑
	logoPath := "assets/logo.png"

	// 開啟檔案
	file, err := os.Open(logoPath)
	if err != nil {
		http.Error(w, "Logo not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// 設定 Content-Type 為圖片格式
	w.Header().Set("Content-Type", "image/png")

	// 將檔案內容寫入回應
	if _, err := io.Copy(w, file); err != nil {
		http.Error(w, "Error serving logo", http.StatusInternalServerError)
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/upload", uploadFileHandler).Methods("POST")
	router.HandleFunc("/thumbnails", listThumbnailsHandler).Methods("GET")
	router.HandleFunc("/video/{videoName}", deleteFileHandler).Methods("DELETE")
	router.HandleFunc("/asset/logo", logoHandler).Methods("GET")
	// 使用 gorilla/handlers 套件處理 CORS
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS", "DELETE"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)(router)

	fmt.Printf("Server running at http://0.0.0.0:%s\n", Port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+Port, corsHandler))
}
