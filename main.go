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
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	supa "github.com/nedpals/supabase-go"
	"github.com/supabase-community/supabase-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	SupabaseURL     string
	SupabaseAPIKey  string
	Port            string
	StorageEndpoint = "/storage/v1/object"
	oauthConfig     *oauth2.Config

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
)

const (
	SupabaseVideosBucket     = "videos"
	SupabaseThumbnailsBucket = "thumbnails"
)

// Claims 結構，用來儲存 JWT 內的 Payload
type Claims struct {
	Email    string `json:"email"`
	UserID   int32  `json:"user_id"`
	UserName string `json:"name"`
	Image    string `json:"image"`
	jwt.RegisteredClaims
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
	requiredEnv := []string{"SUPABASE_BUCKET", "SUPABASE_URL", "SUPABASE_API_KEY", "PORT"}
	for _, env := range requiredEnv {
		if os.Getenv(env) == "" {
			log.Fatalf("環境變數 %s 未設定", env)
		}
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

// 上傳影片並生成縮圖
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
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

	// 上傳影片到 Supabase
	uploadToSupabase(SupabaseVideosBucket, videoPath, hashedFileName, handler.Header.Get("Content-Type"))

	// 上傳縮圖到 Supabase
	thumbnailName := strings.Replace(hashedFileName, filepath.Ext(hashedFileName), ".jpg", 1)
	uploadToSupabase(SupabaseThumbnailsBucket, thumbnailPath, thumbnailName, "image/jpeg")

	// 構建 Supabase 中的 video_path 和 thumbnail_path
	videoURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseVideosBucket, hashedFileName)
	thumbnailURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseThumbnailsBucket, thumbnailName)

	err = videoInsert(originalFileName, videoURL, thumbnailURL)
	if err != nil {
		log.Fatalf("Failed to insert video: %+v", err)
		http.Error(w, "Error inserting record to database", http.StatusInternalServerError)
		return
	}

	video, err := videoGet(videoURL, thumbnailURL)
	if err != nil {
		log.Fatalf("Failed to get video: %+v", err)
		http.Error(w, "Error getting record from database", http.StatusInternalServerError)
		return
	}
	err = userVideoInsert(r.Context().Value("userID").(int32), (video.ID))
	if err != nil {
		log.Fatalf("Failed to insert user_video: %+v", err)
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
	VideoID      int32  `json:"videoID"`
}

func listThumbnailsHandler(w http.ResponseWriter, r *http.Request) {
	videos, err := getVideoByUser(r.Context().Value("userID").(int32))
	if err != nil {
		log.Fatalf("Failed to get videos: %+v", err)
		http.Error(w, "Error getting records from database", http.StatusInternalServerError)
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
		thumbnailSignedUrlResp, err := supabase.Storage.CreateSignedUrl(SupabaseThumbnailsBucket, strings.TrimPrefix(video.Thumbnail_path, fmt.Sprintf("%s/%s/", SupabaseURL, SupabaseThumbnailsBucket)), 86400)
		if err != nil {
			log.Fatalf("Failed to get thumbnail signed URL: %+v", err)
			http.Error(w, "Error getting thumbnail signed URL", http.StatusInternalServerError)
			return
		}

		videoSignedUrlResp, err := supabase.Storage.CreateSignedUrl(SupabaseVideosBucket, strings.TrimPrefix(video.Video_path, fmt.Sprintf("%s/%s/", SupabaseURL, SupabaseVideosBucket)), 86400)
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

	// 回傳 JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := thumbnailResponse{Thumbnails: thumbnails}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

func getVideoByUser(userID int32) ([]Video, error) {
	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("cannot initalize client: %v", err)
		return nil, err
	}

	videos := []Video{}
	userVideos := []UserVideo{}
	// Get all videos by User, using the User ID
	_, err = supabase.
		From("user_videos").
		Select("*", "exact", false).
		Filter("user_id", "eq", strconv.Itoa(int(userID))).
		ExecuteTo(&userVideos)
	if err != nil {
		log.Fatalf("error getting user videos: %v", err)
		return nil, err
	}
	for _, userVideo := range userVideos {
		video := Video{}
		_, err = supabase.
			From("videos").
			Select("*", "exact", false).
			Eq("id", strconv.Itoa(int(userVideo.VideoId))).
			Single().
			ExecuteTo(&video)
		if err != nil {
			log.Fatalf("error getting video by id: %v", err)
			return nil, err
		}
		videos = append(videos, video)
	}
	return videos, nil
}

func videoGetByID(videoID string) (*Video, error) {
	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("cannot initalize client: %v", err)
		return nil, err
	}

	video := Video{}
	_, err = supabase.
		From("videos").
		Select("*", "exact", false).
		Eq("id", videoID).
		Single().
		ExecuteTo(&video)

	if err != nil {
		return nil, err
	}
	return &video, nil
}

// 刪除影片和縮圖
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	// 解析 URL 參數
	vars := mux.Vars(r)
	videoID := vars["videoID"]
	video, err := videoGetByID(videoID)
	if err != nil {
		log.Fatalf("Failed to get video: %+v", err)
		http.Error(w, "Error getting record from database", http.StatusInternalServerError)
		return
	}
	// 刪除影片檔案
	err = deleteFromSupabase(SupabaseVideosBucket, strings.TrimPrefix(video.Video_path, fmt.Sprintf("%s/videos/", SupabaseURL)))
	if err != nil {
		http.Error(w, "Error deleting video", http.StatusInternalServerError)
		return
	}

	// 刪除縮圖檔案（假設縮圖與影片檔案有相同名稱，但副檔名為 .jpg）

	err = deleteFromSupabase(SupabaseThumbnailsBucket, strings.TrimPrefix(video.Video_path, fmt.Sprintf("%s/thumbnails/", SupabaseURL)))
	if err != nil {
		http.Error(w, "Error deleting thumbnail", http.StatusInternalServerError)
		return
	}

	err = videoDelete(video.Name)
	if err != nil {
		log.Fatalf("Failed to delete video: %+v", err)
		http.Error(w, "Error deleting record from database", http.StatusInternalServerError)
		return
	}
	err = userVideoDelete(r.Context().Value("userID").(int32), video.ID)
	if err != nil {
		log.Fatalf("Failed to delete user_video: %+v", err)
		http.Error(w, "Error deleting record from database", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Video and thumbnail deleted successfully: %s", video.Name)))
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

func generateStateOauthCookie(w http.ResponseWriter) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	return state
}

// JWT 驗證 Middleware
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Fatalf("未提供授權 Token")
			http.Error(w, "未提供授權 Token", http.StatusUnauthorized)
			return
		}

		// Token 格式: "Bearer <token>"
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			log.Fatalf("無效的 Token 格式")
			http.Error(w, "無效的 Token 格式", http.StatusUnauthorized)
			return
		}

		// 解析 Token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			log.Fatalf("無效的 Token: %v", err)
			http.Error(w, "無效的 Token", http.StatusUnauthorized)
			return
		}

		// 將用戶資訊存入 Context，讓後續處理可使用
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "userEmail", claims.Email)
		ctx = context.WithValue(ctx, "userName", claims.UserName)
		ctx = context.WithValue(ctx, "userImage", claims.Image)
		log.Printf("User %s authenticated", claims.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// 處理登入請求，導向 Google OAuth 認證
func loginHandler(w http.ResponseWriter, r *http.Request) {
	oauthState := generateStateOauthCookie(w)
	url := oauthConfig.AuthCodeURL(oauthState, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	log.Printf("Redirecting to %s", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// 處理 Google OAuth 回調
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// 取得授權碼
	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Fatalf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to get access token", http.StatusInternalServerError)
		return
	}

	// 取得使用者資訊
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		log.Fatalf("Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 解析使用者資訊
	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}
	log.Printf("User info: %v", userInfo)

	if exist, err := userIsExist(userInfo["email"].(string)); err == nil && !exist {
		log.Println("user not existed, insert user")
		err := userInsert(userInfo["email"].(string), userInfo["name"].(string), userInfo["id"].(string))
		if err != nil {
			log.Printf("Failed to insert user: %+v", err)
			http.Error(w, fmt.Sprintf("Failed to insert user: %+v", err), http.StatusInternalServerError)
			return
		}
	} else if err != nil {
		log.Printf("Failed to check if user is existed: %+v", err)
		http.Error(w, fmt.Sprintf("Failed to check if user is existed: %+v", err), http.StatusInternalServerError)
		return
	}

	user, err := userGet(userInfo["email"].(string))
	if err != nil {
		log.Printf("Failed to get user: %+v", err)
		http.Error(w, fmt.Sprintf("Failed to get user: %+v", err), http.StatusInternalServerError)
		return
	}
	userInfo["id"] = user.ID

	// 這裡可以選擇用 JWT 來建立登入 token
	jwtToken, err := generateJWT(userInfo)
	if err != nil {
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}
	// 重導向回前端首頁，並帶上 token
	redirectURL := fmt.Sprintf("https://sportaii.com?token=%s", jwtToken)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

type User struct {
	ID          int32     `json:"id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Platform_id string    `json:"platform_id"`
	Created_at  time.Time `json:"created_at"`
}

func userIsExist(email string) (bool, error) {
	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("cannot initalize client: %v", err)
		return false, err
	}
	users := []User{}
	count, err := supabase.From("users").Select("*", "exact", false).Eq("email", email).ExecuteTo(&users)
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

func userGet(email string) (*User, error) {
	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("cannot initalize client: %v", err)
		return nil, err
	}

	user := User{}
	_, err = supabase.From("users").Select("*", "exact", false).Eq("email", email).Single().ExecuteTo(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

type Video struct {
	ID             int32     `json:"id"`
	Name           string    `json:"name"`
	Video_path     string    `json:"video_path"`
	Thumbnail_path string    `json:"thumbnail_path"`
	Created_at     time.Time `json:"created_at"`
	Deleted_at     time.Time `json:"deleted_at"`
}

func videoInsert(name, videoPath, thumbnailPath string) error {
	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("cannot initalize client: %v", err)
		return err
	}

	newVideo := Video{
		Name:           name,
		Video_path:     videoPath,
		Thumbnail_path: thumbnailPath,
		Created_at:     time.Now(),
	}

	var insertedVideos []Video
	_, err = supabase.
		From("videos").
		Insert(newVideo, false, "", "", "exact").
		ExecuteTo(&insertedVideos)

	if err != nil {
		return err
	}
	log.Println("insert video successfully:", insertedVideos)
	return nil
}

func videoGet(videoPath, thumbnailPath string) (*Video, error) {
	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("cannot initalize client: %v", err)
		return nil, err
	}

	video := Video{}
	_, err = supabase.
		From("videos").
		Select("*", "exact", false).
		Eq("video_path", videoPath).
		Eq("thumbnail_path", thumbnailPath).
		Single().
		ExecuteTo(&video)

	if err != nil {
		return nil, err
	}
	return &video, nil
}

func videoDelete(videoName string) error {
	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	var deletedVideos []Video
	err := supabase.DB.From("videos").
		Delete().
		Eq("name", videoName).
		Execute(&deletedVideos)

	if err != nil {
		return err
	}
	log.Println("delete video successfully:", deletedVideos)
	return nil
}

type UserVideo struct {
	ID      int32 `json:"id"`
	UserID  int32 `json:"user_id"`
	VideoId int32 `json:"video_id"`
}

func userVideoInsert(userID, videoID int32) error {
	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	newUserVideo := UserVideo{
		UserID:  userID,
		VideoId: videoID,
	}

	var insertedUserVideos []UserVideo
	err := supabase.DB.From("user_videos").
		Insert(newUserVideo).
		Execute(&insertedUserVideos)

	if err != nil {
		return err
	}
	log.Println("insert user_video successfully:", insertedUserVideos)
	return nil
}

func userVideoDelete(userID, videoID int32) error {
	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	var deletedUserVideos []UserVideo
	err := supabase.DB.From("user_videos").
		Delete().
		Eq("user_id", strconv.Itoa(int(userID))).
		Eq("video_id", strconv.Itoa(int(videoID))).
		Execute(&deletedUserVideos)

	if err != nil {
		return err
	}
	log.Println("delete user_video successfully:", deletedUserVideos)
	return nil
}

func userInsert(email, name, platformID string) error {
	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	newUser := User{
		Email:       email,
		Name:        name,
		Platform_id: platformID,
		Created_at:  time.Now(),
	}

	var insertedUsers []User
	err := supabase.DB.From("users").
		Insert(newUser).
		Execute(&insertedUsers)

	if err != nil {
		return err
	}
	log.Println("insert user successfully:", insertedUsers)
	return nil
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

// generateJWT 產生 JWT Token
func generateJWT(userInfo map[string]interface{}) (string, error) {
	// 設定 Token 過期時間
	expirationTime := time.Now().Add(24 * time.Hour)

	// 建立 claims
	claims := jwt.MapClaims{
		"email":   userInfo["email"].(string),
		"user_id": userInfo["id"].(int32),
		"image":   userInfo["picture"].(string),
		"name":    userInfo["name"].(string),
		"exp":     expirationTime.Unix(), // 過期時間
		"iat":     time.Now().Unix(),     // 發行時間
	}

	// 產生 Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 簽名 Token
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
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

// CORS Middleware
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
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Remove the separate handleOptions function as it's now handled in the middleware

func main() {
	router := mux.NewRouter()

	router.Use(corsMiddleware)
	router.Use(loggingMiddleware)

	protectedRoutes := router.PathPrefix("/").Subrouter()
	protectedRoutes.Use(jwtMiddleware)

	// Remove separate OPTIONS handlers from route definitions
	protectedRoutes.HandleFunc("/api/user", getCurrentUserHandler).Methods("GET", "OPTIONS")
	protectedRoutes.HandleFunc("/upload", uploadFileHandler).Methods("POST", "OPTIONS")
	protectedRoutes.HandleFunc("/thumbnails", listThumbnailsHandler).Methods("GET", "OPTIONS")
	protectedRoutes.HandleFunc("/video/{videoID}", deleteFileHandler).Methods("DELETE", "OPTIONS")

	router.HandleFunc("/asset/logo", logoHandler).Methods("GET")
	router.HandleFunc("/auth/google/login", loginHandler).Methods("GET")
	router.HandleFunc("/auth/google/callback", callbackHandler).Methods("GET")

	fmt.Printf("Server running at http://0.0.0.0:%s\n", Port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+Port, router))
}
