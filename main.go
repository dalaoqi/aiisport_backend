package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/supabase-community/supabase-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	SupabaseURL     string
	SupabaseAPIKey  string
	Port            string
	StorageEndpoint = "/storage/v1/object"
	oauthConfig     *oauth2.Config
	jwtSecret       = []byte(os.Getenv("JWT_SECRET"))
	DB              *gorm.DB // GORM 資料庫實例
)

const (
	SupabaseVideosBucket     = "videos"
	SupabaseThumbnailsBucket = "thumbnails"
)

// Claims 結構，用來儲存 JWT 內的 Payload
type Claims struct {
	Email    string `json:"email"`
	UserID   string `json:"user_id"`
	UserName string `json:"name"`
	Image    string `json:"image"`
	jwt.RegisteredClaims
}

type User struct {
	ID         string    `gorm:"type:uuid;primaryKey" json:"id"`
	Email      string    `gorm:"type:text;not null;unique" json:"email"`
	Name       string    `gorm:"type:text;not null" json:"name"`
	PlatformID string    `gorm:"type:text;not null" json:"platform_id"`
	CreatedAt  time.Time `gorm:"default:now()" json:"created_at"`
}

type Video struct {
	ID            string    `gorm:"type:uuid;primaryKey" json:"id"`
	Name          string    `gorm:"type:text;not null" json:"name"`
	VideoPath     string    `gorm:"type:text;not null" json:"video_path"`
	ThumbnailPath string    `gorm:"type:text;not null" json:"thumbnail_path"`
	CreatedAt     time.Time `gorm:"default:now()" json:"created_at"`
	DeletedAt     time.Time `gorm:"default:'0001-01-01 00:00:00+00'" json:"deleted_at"`
}

type UserVideo struct {
	ID      string `gorm:"type:uuid;primaryKey" json:"id"`
	UserID  string `gorm:"type:uuid;not null" json:"user_id"`
	VideoID string `gorm:"type:uuid;not null" json:"video_id"`
}

type Highlight struct {
	ID          string          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VideoID     string          `gorm:"type:uuid;not null" json:"video_id"`
	StartTime   *int            `gorm:"null" json:"start_time"`
	EndTime     *int            `gorm:"null" json:"end_time"`
	Description *string         `gorm:"type:text;null" json:"description"`
	CreatedAt   time.Time       `gorm:"default:now()" json:"created_at"`
	DeletedAt   time.Time       `gorm:"default:'0001-01-01 00:00:00+00'" json:"deleted_at"`
	Video       Video           `gorm:"foreignKey:VideoID;references:ID;constraint:OnDelete:CASCADE"`
	Types       []HighlightType `gorm:"many2many:highlight_highlight_types;"`
}

type HighlightType struct {
	ID          int       `gorm:"primaryKey;autoIncrement" json:"id"`
	Name        string    `gorm:"type:text;not null;unique" json:"name"`
	Description *string   `gorm:"type:text;null" json:"description"`
	CreatedAt   time.Time `gorm:"default:now()" json:"created_at"`
	DeletedAt   time.Time `gorm:"default:'0001-01-01 00:00:00+00'" json:"deleted_at"`
}

type HighlightHighlightType struct {
	HighlightID     string    `gorm:"type:uuid;primaryKey" json:"highlight_id"`
	HighlightTypeID int       `gorm:"primaryKey" json:"highlight_type_id"`
	CreatedAt       time.Time `gorm:"default:now()" json:"created_at"`
}

type HighlightResponse struct {
	ID             string              `json:"id"`
	VideoID        string              `json:"video_id"`
	HighlightTypes []HighlightTypeData `json:"highlight_types"`
	StartTime      *int                `json:"start_time"`
	EndTime        *int                `json:"end_time"`
	Description    *string             `json:"description"`
	CreatedAt      string              `json:"created_at"`
}

type HighlightTypeData struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

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
	requiredEnv := []string{"SUPABASE_URL", "SUPABASE_API_KEY", "PORT", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_PORT"}
	for _, env := range requiredEnv {
		if os.Getenv(env) == "" {
			log.Fatalf("環境變數 %s 未設定", env)
		}
	}

	// 初始化 GORM 資料庫連接
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("無法連接到資料庫: %v", err)
	}

	// 自動遷移資料庫結構
	if err := DB.AutoMigrate(&User{}, &Video{}, &UserVideo{}, &Highlight{}, &HighlightType{}); err != nil {
		log.Fatalf("資料庫遷移失敗: %v", err)
	}

	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	log.Printf("OAuth Config: %v", oauthConfig.RedirectURL)
}

func getVideoHighlightsHandler(w http.ResponseWriter, r *http.Request) {
	// 從 URL 參數中獲取 videoID
	vars := mux.Vars(r)
	videoID := vars["videoID"]

	// 檢查 video 是否存在
	var video Video
	if err := DB.Where("id = ?", videoID).First(&video).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "Video not found", http.StatusNotFound)
			return
		}
		log.Printf("Failed to get video: %v", err)
		http.Error(w, "Error retrieving video", http.StatusInternalServerError)
		return
	}

	// 查詢該 video 的所有 highlights，並預載入相關的 HighlightTypes
	var highlights []Highlight
	if err := DB.Preload("Types").Where("video_id = ?", videoID).Find(&highlights).Error; err != nil {
		log.Printf("Failed to get highlights: %v", err)
		http.Error(w, "Error retrieving highlights", http.StatusInternalServerError)
		return
	}

	// 轉換為回應結構
	var response []HighlightResponse
	for _, h := range highlights {
		var highlightTypes []HighlightTypeData
		for _, ht := range h.Types {
			highlightTypes = append(highlightTypes, HighlightTypeData{
				ID:          ht.ID,
				Name:        ht.Name,
				Description: ht.Description,
			})
		}

		response = append(response, HighlightResponse{
			ID:             h.ID,
			VideoID:        h.VideoID,
			HighlightTypes: highlightTypes,
			StartTime:      h.StartTime,
			EndTime:        h.EndTime,
			Description:    h.Description,
			CreatedAt:      h.CreatedAt.Format(time.RFC3339),
		})
	}

	// 回傳 JSON 回應
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

// 上傳影片並生成縮圖
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(100 << 20) // 限制上傳檔案大小 100 MB
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
	defer os.Remove(videoPath)

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

	// 上傳影片和縮圖到 Supabase（這裡假設您仍使用 Supabase Storage）
	uploadToSupabase(SupabaseVideosBucket, videoPath, hashedFileName, handler.Header.Get("Content-Type"))
	thumbnailName := strings.Replace(hashedFileName, filepath.Ext(hashedFileName), ".jpg", 1)
	uploadToSupabase(SupabaseThumbnailsBucket, thumbnailPath, thumbnailName, "image/jpeg")

	// 構建 Supabase 中的 video_path 和 thumbnail_path
	videoURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseVideosBucket, hashedFileName)
	thumbnailURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseThumbnailsBucket, thumbnailName)

	// 使用 GORM 插入影片資料
	newVideo := Video{
		ID:            uuid.New().String(),
		Name:          originalFileName,
		VideoPath:     videoURL,
		ThumbnailPath: thumbnailURL,
		CreatedAt:     time.Now(),
	}
	if err := DB.Create(&newVideo).Error; err != nil {
		log.Printf("Failed to insert video: %v", err)
		http.Error(w, "Error inserting record to database", http.StatusInternalServerError)
		return
	}

	// 插入 user_videos 關聯
	userID := r.Context().Value("userID").(string)
	newUserVideo := UserVideo{
		ID:      uuid.New().String(),
		UserID:  userID,
		VideoID: newVideo.ID,
	}
	if err := DB.Create(&newUserVideo).Error; err != nil {
		log.Printf("Failed to insert user_video: %v", err)
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

// 上傳檔案到 Supabase Storage（未改動，因為這部分與資料庫無關）
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
	req.Header.Set("x-upsert", "true")

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
	VideoID      string `json:"videoID"`
}

func listThumbnailsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)
	videos, err := getVideoByUser(userID)
	if err != nil {
		log.Printf("Failed to get videos: %v", err)
		http.Error(w, "Error getting videos", http.StatusInternalServerError)
		return
	}

	var thumbnails []thumbnailData
	thumbnails = make([]thumbnailData, 0)

	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("cannot initalize client: %v", err)
		http.Error(w, "Error initializing client", http.StatusInternalServerError)
		return
	}

	for _, video := range videos {
		thumbnailSignedUrlResp, err := supabase.Storage.CreateSignedUrl(SupabaseThumbnailsBucket, strings.TrimPrefix(video.ThumbnailPath, fmt.Sprintf("%s/%s/", SupabaseURL, SupabaseThumbnailsBucket)), 86400)
		if err != nil {
			log.Fatalf("Failed to get thumbnail signed URL: %+v", err)
			http.Error(w, "Error getting thumbnail signed URL", http.StatusInternalServerError)
			return
		}

		videoSignedUrlResp, err := supabase.Storage.CreateSignedUrl(SupabaseVideosBucket, strings.TrimPrefix(video.VideoPath, fmt.Sprintf("%s/%s/", SupabaseURL, SupabaseVideosBucket)), 86400)
		if err != nil {
			log.Fatalf("Failed to get video signed URL: %+v", err)
			http.Error(w, "Error getting video signed URL", http.StatusInternalServerError)
			return
		}
		thumbnails = append(thumbnails, thumbnailData{
			ThumbnailURL: thumbnailSignedUrlResp.SignedURL,
			VideoURL:     videoSignedUrlResp.SignedURL,
			VideoName:    video.Name,
			VideoID:      video.ID,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := thumbnailResponse{Thumbnails: thumbnails}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

func getVideoByUser(userID string) ([]Video, error) {
	var userVideos []UserVideo
	if err := DB.Where("user_id = ?", userID).Find(&userVideos).Error; err != nil {
		return nil, err
	}

	var videos []Video
	for _, uv := range userVideos {
		var video Video
		if err := DB.Where("id = ?", uv.VideoID).First(&video).Error; err != nil {
			continue
		}
		videos = append(videos, video)
	}
	return videos, nil
}

func videoGetByID(videoID string) (*Video, error) {
	var video Video
	if err := DB.Where("id = ?", videoID).First(&video).Error; err != nil {
		return nil, err
	}
	return &video, nil
}

func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	videoID := vars["videoID"]

	video, err := videoGetByID(videoID)
	if err != nil {
		log.Printf("Failed to get video: %v", err)
		http.Error(w, "Error getting record from database", http.StatusInternalServerError)
		return
	}

	// 刪除 Supabase Storage 中的檔案
	err = deleteFromSupabase(SupabaseVideosBucket, strings.TrimPrefix(video.VideoPath, fmt.Sprintf("%s/videos/", SupabaseURL)))
	if err != nil {
		http.Error(w, "Error deleting video", http.StatusInternalServerError)
		return
	}
	err = deleteFromSupabase(SupabaseThumbnailsBucket, strings.TrimPrefix(video.ThumbnailPath, fmt.Sprintf("%s/thumbnails/", SupabaseURL)))
	if err != nil {
		http.Error(w, "Error deleting thumbnail", http.StatusInternalServerError)
		return
	}

	// 使用 GORM 刪除資料庫記錄
	if err := DB.Where("id = ?", videoID).Delete(&Video{}).Error; err != nil {
		log.Printf("Failed to delete video: %v", err)
		http.Error(w, "Error deleting record from database", http.StatusInternalServerError)
		return
	}
	if err := DB.Where("user_id = ? AND video_id = ?", r.Context().Value("userID").(string), videoID).Delete(&UserVideo{}).Error; err != nil {
		log.Printf("Failed to delete user_video: %v", err)
		http.Error(w, "Error deleting record from database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Video and thumbnail deleted successfully: %s", video.Name)))
}

// 從 Supabase Storage 刪除檔案（未改動）
func deleteFromSupabase(bucket, fileName string) error {
	// 這裡假設仍使用 Supabase Storage，保留原有邏輯
	uploadURL := fmt.Sprintf("%s%s/%s/%s", SupabaseURL, StorageEndpoint, bucket, fileName)
	req, err := http.NewRequest("DELETE", uploadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+SupabaseAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error deleting file: %s", string(body))
	}
	return nil
}

func logoHandler(w http.ResponseWriter, r *http.Request) {
	logoPath := "assets/logo.png"
	file, err := os.Open(logoPath)
	if err != nil {
		http.Error(w, "Logo not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "image/png")
	if _, err := io.Copy(w, file); err != nil {
		http.Error(w, "Error serving logo", http.StatusInternalServerError)
	}
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "未提供授權 Token", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "無效的 Token 格式", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "無效的 Token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "userEmail", claims.Email)
		ctx = context.WithValue(ctx, "userName", claims.UserName)
		ctx = context.WithValue(ctx, "userImage", claims.Image)
		log.Printf("User %s authenticated", claims.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	oauthState := generateStateOauthCookie(w)
	url := oauthConfig.AuthCodeURL(oauthState, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to get access token", http.StatusInternalServerError)
		return
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	var user User
	if err := DB.Where("email = ?", userInfo["email"].(string)).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			user = User{
				ID:         uuid.New().String(),
				Email:      userInfo["email"].(string),
				Name:       userInfo["name"].(string),
				PlatformID: userInfo["id"].(string),
				CreatedAt:  time.Now(),
			}
			if err := DB.Create(&user).Error; err != nil {
				http.Error(w, fmt.Sprintf("Failed to insert user: %v", err), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, fmt.Sprintf("Failed to check user: %v", err), http.StatusInternalServerError)
			return
		}
	}

	userInfo["id"] = user.ID
	jwtToken, err := generateJWT(userInfo)
	if err != nil {
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("https://sportaii.com?token=%s", jwtToken)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func userIsExist(email string) (bool, error) {
	var count int64
	if err := DB.Model(&User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func userGet(email string) (*User, error) {
	var user User
	if err := DB.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func videoInsert(name, videoPath, thumbnailPath string) error {
	newVideo := Video{
		ID:            uuid.New().String(),
		Name:          name,
		VideoPath:     videoPath,
		ThumbnailPath: thumbnailPath,
		CreatedAt:     time.Now(),
	}
	return DB.Create(&newVideo).Error
}

func videoGet(videoPath, thumbnailPath string) (*Video, error) {
	var video Video
	if err := DB.Where("video_path = ? AND thumbnail_path = ?", videoPath, thumbnailPath).First(&video).Error; err != nil {
		return nil, err
	}
	return &video, nil
}

func videoDelete(videoID string) error {
	return DB.Where("id = ?", videoID).Delete(&Video{}).Error
}

func userVideoInsert(userID, videoID string) error {
	newUserVideo := UserVideo{
		ID:      uuid.New().String(),
		UserID:  userID,
		VideoID: videoID,
	}
	return DB.Create(&newUserVideo).Error
}

func userVideoDelete(userID, videoID string) error {
	return DB.Where("user_id = ? AND video_id = ?", userID, videoID).Delete(&UserVideo{}).Error
}

func userInsert(email, name, platformID string) error {
	newUser := User{
		ID:         uuid.New().String(),
		Email:      email,
		Name:       name,
		PlatformID: platformID,
		CreatedAt:  time.Now(),
	}
	return DB.Create(&newUser).Error
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}
		log.Printf("[%s] %s %s from %s", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.URL.Path, ip)
		next.ServeHTTP(w, r)
	})
}

func generateJWT(userInfo map[string]interface{}) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"email":   userInfo["email"].(string),
		"user_id": userInfo["id"].(string),
		"image":   userInfo["picture"].(string),
		"name":    userInfo["name"].(string),
		"exp":     expirationTime.Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func getCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"userEmail": r.Context().Value("userEmail").(string),
		"userName":  r.Context().Value("userName").(string),
		"userImage": r.Context().Value("userImage").(string),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigins := map[string]bool{
			"https://sportaii.com": true,
		}

		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Range")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	router := mux.NewRouter()

	router.Use(corsMiddleware)
	router.Use(loggingMiddleware)

	protectedRoutes := router.PathPrefix("/").Subrouter()
	protectedRoutes.Use(jwtMiddleware)

	// 現有路由
	protectedRoutes.HandleFunc("/api/user", getCurrentUserHandler).Methods("GET", "OPTIONS")
	protectedRoutes.HandleFunc("/upload", uploadFileHandler).Methods("POST", "OPTIONS")
	protectedRoutes.HandleFunc("/thumbnails", listThumbnailsHandler).Methods("GET", "OPTIONS")
	protectedRoutes.HandleFunc("/video/{videoID}", deleteFileHandler).Methods("DELETE", "OPTIONS")

	// 新增的路由
	protectedRoutes.HandleFunc("/video/{videoID}/highlights", getVideoHighlightsHandler).Methods("GET", "OPTIONS")

	router.HandleFunc("/asset/logo", logoHandler).Methods("GET")
	router.HandleFunc("/auth/google/login", loginHandler).Methods("GET")
	router.HandleFunc("/auth/google/callback", callbackHandler).Methods("GET")

	fmt.Printf("Server running at http://0.0.0.0:%s\n", Port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+Port, router))
}
