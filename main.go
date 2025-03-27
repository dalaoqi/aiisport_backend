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
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hibiken/asynq"
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
	DB              *gorm.DB // GORM database instance

	taskClient *asynq.Client
	taskServer *asynq.Server
)

const (
	SupabaseVideosBucket           = "videos"
	SupabaseThumbnailsBucket       = "thumbnails"
	SupabaseHighlightsBucket       = "highlights"
	SupabaseMergedHighlightsBucket = "merged-highlights"
	SupabaseMergedThumbnailsBucket = "merged-thumbnails"
)

// Claims struct for storing JWT payload
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
	ID            string          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VideoID       string          `gorm:"type:uuid;not null" json:"video_id"`
	HighlightPath string          `gorm:"type:text;not null" json:"highlight_path"` // 新增
	ThumbnailPath string          `gorm:"type:text;not null" json:"thumbnail_path"` // 新增
	Description   *string         `gorm:"type:text;null" json:"description"`
	CreatedAt     time.Time       `gorm:"default:now()" json:"created_at"`
	DeletedAt     time.Time       `gorm:"default:'0001-01-01 00:00:00+00'" json:"deleted_at"`
	Video         Video           `gorm:"foreignKey:VideoID;references:ID;constraint:OnDelete:CASCADE"`
	Types         []HighlightType `gorm:"many2many:highlight_highlight_types;"` // 多對多關聯
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
	HighlightPath  string              `json:"highlight_path"`
	ThumbnailPath  string              `json:"thumbnail_path"`
	HighlightTypes []HighlightTypeData `json:"highlight_types"`
	Description    *string             `json:"description"`
	CreatedAt      string              `json:"created_at"`
}

type HighlightTypeData struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

// Store merged video information
type MergedVideo struct {
	ID            string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name          string    `gorm:"type:text;not null" json:"name"`
	VideoPath     string    `gorm:"type:text;not null" json:"video_path"`
	ThumbnailPath string    `gorm:"type:text;not null" json:"thumbnail_path"`
	Description   *string   `gorm:"type:text;null" json:"description"`
	UserID        string    `gorm:"type:uuid;not null" json:"user_id"`
	User          User      `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
	Status        string    `gorm:"type:text;not null;default:'queued'" json:"status"` // 新增狀態欄位
	CreatedAt     time.Time `gorm:"default:now()" json:"created_at"`
	UpdatedAt     time.Time `gorm:"default:now()" json:"updated_at"` // 新增更新時間
	DeletedAt     time.Time `gorm:"default:'0001-01-01 00:00:00+00'" json:"deleted_at"`
}

// Store association between merged video and original highlights
type MergedVideoHighlight struct {
	MergedVideoID string      `gorm:"type:uuid;primaryKey" json:"merged_video_id"`
	HighlightID   string      `gorm:"type:uuid;primaryKey" json:"highlight_id"`
	MergedVideo   MergedVideo `gorm:"foreignKey:MergedVideoID;references:ID;constraint:OnDelete:CASCADE"`
	Highlight     Highlight   `gorm:"foreignKey:HighlightID;references:ID;constraint:OnDelete:CASCADE"`
	CreatedAt     time.Time   `gorm:"default:now()" json:"created_at"`
}

func init() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, trying to use system environment variables")
	}

	// Load necessary settings from environment variables
	SupabaseURL = os.Getenv("SUPABASE_URL")
	SupabaseAPIKey = os.Getenv("SUPABASE_API_KEY")
	Port = os.Getenv("PORT")

	// Check if necessary environment variables are set
	requiredEnv := []string{"SUPABASE_URL", "SUPABASE_API_KEY", "PORT", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_PORT"}
	for _, env := range requiredEnv {
		if os.Getenv(env) == "" {
			log.Fatalf("Environment variable %s is not set", env)
		}
	}

	// Initialize GORM database connection
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	log.Printf("OAuth Config: %v", oauthConfig.RedirectURL)

	initTaskSystem()
}

// Initialize Redis and Asynq
func initTaskSystem() {
	taskClient = asynq.NewClient(asynq.RedisClientOpt{
		Addr: os.Getenv("REDIS_HOST"),
	})

	taskServer = asynq.NewServer(
		asynq.RedisClientOpt{Addr: os.Getenv("REDIS_HOST")},
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
		},
	)
}

func getVideoHighlightsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	videoID := vars["videoID"]

	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
		http.Error(w, "Error initializing client", http.StatusInternalServerError)
		return
	}

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

	var highlights []Highlight
	if err := DB.Preload("Types").Where("video_id = ?", videoID).Find(&highlights).Error; err != nil {
		log.Printf("Failed to get highlights: %v", err)
		http.Error(w, "Error retrieving highlights", http.StatusInternalServerError)
		return
	}

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

		highlightSignedUrlResp, err := supabase.Storage.CreateSignedUrl(SupabaseVideosBucket, strings.TrimPrefix(h.HighlightPath, fmt.Sprintf("%s/%s/", SupabaseURL, SupabaseVideosBucket)), 86400)
		if err != nil {
			log.Fatalf("Failed to get highlight signed URL: %+v", err)
			http.Error(w, "Error getting highlight signed URL", http.StatusInternalServerError)
			return
		}

		thumbnailSignedUrlResp, err := supabase.Storage.CreateSignedUrl(SupabaseThumbnailsBucket, strings.TrimPrefix(h.ThumbnailPath, fmt.Sprintf("%s/%s/", SupabaseURL, SupabaseThumbnailsBucket)), 86400)
		if err != nil {
			log.Fatalf("Failed to get thumbnail signed URL: %+v", err)
			http.Error(w, "Error getting thumbnail signed URL", http.StatusInternalServerError)
			return
		}
		response = append(response, HighlightResponse{
			ID:             h.ID,
			VideoID:        h.VideoID,
			HighlightPath:  highlightSignedUrlResp.SignedURL,
			ThumbnailPath:  thumbnailSignedUrlResp.SignedURL,
			HighlightTypes: highlightTypes,
			Description:    h.Description,
			CreatedAt:      h.CreatedAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

// Upload file and generate thumbnail
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(100 << 20) // Limit upload file size to 100 MB
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

	// Create uploads directory
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		if err := os.Mkdir("uploads", 0755); err != nil {
			http.Error(w, "Error creating uploads directory", http.StatusInternalServerError)
			return
		}
	}

	// Get original file name and generate hash
	originalFileName := filepath.Base(handler.Filename)
	hashedFileName := generateHashedFileName(originalFileName) // Includes original file extension
	tempVideoPath := fmt.Sprintf("uploads/%s", hashedFileName) // Temporary storage for original file

	// Check if file extension is .mov
	isMov := strings.ToLower(filepath.Ext(originalFileName)) == ".mov"
	finalVideoPath := tempVideoPath
	finalFileName := hashedFileName

	// Save video to local storage
	outFile, err := os.Create(tempVideoPath)
	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()
	defer os.Remove(tempVideoPath) // Clean up temporary original file

	if _, err := io.Copy(outFile, file); err != nil {
		http.Error(w, "Error writing the file", http.StatusInternalServerError)
		return
	}

	// If not .mov, convert to .mov
	if !isMov {
		finalFileName = strings.TrimSuffix(hashedFileName, filepath.Ext(hashedFileName)) + ".mov"
		finalVideoPath, err := convertVideoToMOV(tempVideoPath, "uploads")
		if err != nil {
			http.Error(w, "Error converting video to .mov", http.StatusInternalServerError)
			return
		}
		defer os.Remove(finalVideoPath) // Clean up converted .mov file
	}

	// Use FFmpeg to generate thumbnail
	thumbnailPath := strings.TrimSuffix(tempVideoPath, filepath.Ext(tempVideoPath)) + ".jpg"
	cmd := exec.Command("ffmpeg", "-i", finalVideoPath, "-ss", "00:00:02", "-vframes", "1", "-q:v", "2", thumbnailPath)
	if err := cmd.Run(); err != nil {
		log.Printf("Error generating thumbnail: %v", err)
		http.Error(w, "Error generating thumbnail", http.StatusInternalServerError)
		return
	}

	// Upload video and thumbnail to Supabase
	uploadToSupabase(SupabaseVideosBucket, finalVideoPath, finalFileName, "video/quicktime")
	thumbnailName := strings.TrimSuffix(hashedFileName, filepath.Ext(hashedFileName)) + ".jpg"
	uploadToSupabase(SupabaseThumbnailsBucket, thumbnailPath, thumbnailName, "image/jpeg")

	// Construct Supabase video_path and thumbnail_path
	videoURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseVideosBucket, finalFileName)
	thumbnailURL := fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseThumbnailsBucket, thumbnailName)

	// Use GORM to insert video data
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

	// Insert user_videos association
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
	w.Write([]byte(fmt.Sprintf("File and thumbnail uploaded successfully: %s", finalFileName)))
}

// Generate hashed file name based on original file name and current time
func generateHashedFileName(fileName string) string {
	currentTime := fmt.Sprintf("%d", time.Now().UnixNano())
	hashInput := fileName + currentTime
	hash := sha256.New()
	hash.Write([]byte(hashInput))
	hashedFileName := fmt.Sprintf("%x%s", hash.Sum(nil), filepath.Ext(fileName))
	return strings.ToLower(hashedFileName)
}

// Upload file to Supabase Storage (unchanged, as it's unrelated to database)
func uploadToSupabase(bucket, filePath, fileName, contentType string) error {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return err
	}
	defer file.Close()

	buffer := bytes.NewBuffer(nil)
	if _, err := io.Copy(buffer, file); err != nil {
		log.Printf("Error reading file: %v", err)
		return err
	}

	uploadURL := fmt.Sprintf("%s%s/%s/%s", SupabaseURL, StorageEndpoint, bucket, fileName)
	req, err := http.NewRequest("POST", uploadURL, buffer)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+SupabaseAPIKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-upsert", "true")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error uploading to Supabase: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error response from Supabase: %s", string(body))
	}
	return nil
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
		log.Fatalf("Failed to initialize client: %v", err)
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

	// Delete file from Supabase Storage
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

	// Use GORM to delete database record
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

// Delete file from Supabase Storage
func deleteFromSupabase(bucket, fileName string) error {
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
			http.Error(w, "No authorization token provided", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
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

// Convert input video file to .mov format
// inputPath: Path to input video file
// outputDir: Directory to output converted file (without filename)
// Returns: Path to converted file and any error
func convertVideoToMOV(inputPath string, outputDir string) (string, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create output directory: %v", err)
	}

	// Get input file name (without path)
	inputFileName := filepath.Base(inputPath)
	// Construct output file path with .mov extension
	outputFileName := inputFileName[:len(inputFileName)-len(filepath.Ext(inputFileName))] + ".mov"
	outputPath := filepath.Join(outputDir, outputFileName)

	// Construct FFmpeg command
	cmd := exec.Command(
		"ffmpeg",
		"-i", inputPath, // Input file
		"-c:v", "libx264", // Video encoding to H.264
		"-c:a", "aac", // Audio encoding to AAC
		"-preset", "medium", // Encoding speed and quality balance
		"-movflags", "faststart", // Optimize MOV file for fast playback
		"-y",       // Automatically overwrite output file
		outputPath, // Output file path
	)

	// Run command and capture any error output
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("conversion failed: %v", err)
	}

	return outputPath, nil
}

type MergeRequest struct {
	HighlightIds []string `json:"highlightIds"`
	Name         string   `json:"name"`
	Description  *string  `json:"description,omitempty"`
}

type MergeResponse struct {
	TaskID string `json:"taskId"`
	Status string `json:"status"`
}

type MergeTaskPayload struct {
	HighlightIds  []string `json:"highlightIds"`
	UserID        string   `json:"userId"`
	Name          string   `json:"name"`
	Description   *string  `json:"description"`
	MergedVideoID string   `json:"mergedVideoId"`
}

func mergeHighlightsHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Validate request
	userID := r.Context().Value("userID").(string)
	log.Printf("Starting video merge request [userID: %s]", userID)

	if userID == "" {
		log.Printf("Unauthorized request [userID empty]")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req MergeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to parse request [userID: %s, error: %v]", userID, err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate at least 2 videos selected
	if len(req.HighlightIds) < 2 {
		log.Printf("Insufficient number of videos [userID: %s, count: %d]", userID, len(req.HighlightIds))
		http.Error(w, "Must select at least 2 videos for merge", http.StatusBadRequest)
		return
	}

	// Validate required parameters
	if req.Name == "" {
		log.Printf("Video name is empty [userID: %s]", userID)
		http.Error(w, "Video name is required", http.StatusBadRequest)
		return
	}

	log.Printf("Querying video information [userID: %s, highlightIds: %v]", userID, req.HighlightIds)
	// 2. Validate video permissions
	var highlights []Highlight
	if err := DB.Where("id IN ?", req.HighlightIds).Find(&highlights).Error; err != nil {
		log.Printf("Failed to query videos [userID: %s, error: %v]", userID, err)
		http.Error(w, "Error querying videos", http.StatusInternalServerError)
		return
	}

	if len(highlights) != len(req.HighlightIds) {
		log.Printf("Some videos not found [userID: %s, requested: %d, found: %d]", userID, len(req.HighlightIds), len(highlights))
		http.Error(w, "Some videos not found", http.StatusNotFound)
		return
	}

	// Check user permissions
	log.Printf("Validating user permissions [userID: %s]", userID)
	for _, h := range highlights {
		var count int64
		DB.Model(&UserVideo{}).
			Joins("JOIN videos ON user_videos.video_id = videos.id").
			Where("user_videos.user_id = ? AND videos.id = ?", userID, h.VideoID).
			Count(&count)
		if count == 0 {
			log.Printf("User has no permission [userID: %s, videoID: %s]", userID, h.VideoID)
			http.Error(w, fmt.Sprintf("No permission to operate on video %v", h.VideoID), http.StatusForbidden)
			return
		}
	}

	mergedFileName := generateHashedFileName(fmt.Sprintf("%s_%s", req.Name, uuid.New().String()))

	mergedVideo := MergedVideo{
		ID:            uuid.New().String(),
		Name:          req.Name,
		VideoPath:     fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseMergedHighlightsBucket, fmt.Sprintf("%s.mov", mergedFileName)),
		ThumbnailPath: fmt.Sprintf("%s/%s/%s", SupabaseURL, SupabaseMergedThumbnailsBucket, fmt.Sprintf("%s.jpg", mergedFileName)),
		UserID:        userID,
		Description:   req.Description,
		Status:        "queued",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := DB.Create(&mergedVideo).Error; err != nil {
		log.Printf("Failed to save merged video record [userID: %s, error: %v]", userID, err)
		http.Error(w, "Unable to create merge task", http.StatusInternalServerError)
		return
	}

	// 3. Create asynchronous task
	log.Printf("Creating merge task [userID: %s, name: %s]", userID, req.Name)
	payload, _ := json.Marshal(MergeTaskPayload{
		HighlightIds:  req.HighlightIds,
		UserID:        userID,
		Name:          mergedFileName,
		Description:   req.Description,
		MergedVideoID: mergedVideo.ID,
	})

	task := asynq.NewTask("merge_highlights", payload)
	_, err := taskClient.Enqueue(task, asynq.Queue("default"))
	if err != nil {
		log.Printf("Failed to create task [userID: %s, error: %v]", userID, err)
		http.Error(w, "Failed to create merge task", http.StatusInternalServerError)
		return
	}

	// 4. Return task information
	resp := MergeResponse{
		TaskID: mergedVideo.ID,
		Status: "queued",
	}

	log.Printf("Task created successfully [userID: %s, mergedVideoID: %s]", userID, mergedVideo.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(resp)
}

// Handle merge task worker
func handleMergeTask(ctx context.Context, t *asynq.Task) error {
	var payload MergeTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		log.Printf("Failed to parse task data [error: %v]", err)
		return fmt.Errorf("Failed to parse task data: %v", err)
	}

	log.Printf("Starting merge task processing [userID: %s, highlightCount: %d]", payload.UserID, len(payload.HighlightIds))

	// Update status to "processing"
	if err := DB.Model(&MergedVideo{}).Where("id = ?", payload.MergedVideoID).Updates(map[string]interface{}{
		"status":     "processing",
		"updated_at": time.Now(),
	}).Error; err != nil {
		log.Printf("Failed to update task status [mergedVideoID: %s, error: %v]", payload.MergedVideoID, err)
		return fmt.Errorf("Failed to update task status: %v", err)
	}

	// Get all highlight paths
	var highlights []Highlight
	if err := DB.Where("id IN ?", payload.HighlightIds).Find(&highlights).Error; err != nil {
		log.Printf("Failed to query videos [userID: %s, error: %v]", payload.UserID, err)
		updateMergedVideoStatus(payload.MergedVideoID, "failed")
		return fmt.Errorf("Failed to query videos: %v", err)
	}

	// Prepare FFmpeg merge
	tempFile := fmt.Sprintf("temp_%s.txt", uuid.New().String())
	outputPath := fmt.Sprintf("uploads/%s.mov", payload.Name)

	log.Printf("Preparing to merge files [userID: %s, outputPath: %s]", payload.UserID, outputPath)

	// Create uploads directory
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		if err := os.Mkdir("uploads", 0755); err != nil {
			log.Printf("Failed to create directory [userID: %s, error: %v]", payload.UserID, err)
			updateMergedVideoStatus(payload.MergedVideoID, "failed")
			return fmt.Errorf("Failed to create uploads directory: %v", err)
		}
	}

	// Create downloads directory
	if _, err := os.Stat("downloads"); os.IsNotExist(err) {
		if err := os.Mkdir("downloads", 0755); err != nil {
			log.Printf("Failed to create directory [userID: %s, error: %v]", payload.UserID, err)
			updateMergedVideoStatus(payload.MergedVideoID, "failed")
			return fmt.Errorf("Failed to create downloads directory: %v", err)
		}
		log.Printf("Downloads directory created successfully [userID: %s]", payload.UserID)
	}

	log.Printf("Starting parallel video downloads [userID: %s, highlightCount: %d]", payload.UserID, len(highlights))
	var localPaths []string
	errChan := make(chan error, len(highlights))
	pathChan := make(chan string, len(highlights))

	for _, h := range highlights {
		go func(highlight Highlight) {
			localPath, err := downloadAndSaveFile(SupabaseVideosBucket, highlight.HighlightPath, "downloads")
			if err != nil {
				log.Printf("Failed to download video [userID: %s, highlightID: %s, error: %v]", payload.UserID, highlight.ID, err)
				errChan <- err
				return
			}
			log.Printf("Video downloaded successfully [userID: %s, highlightID: %s, localPath: %s]", payload.UserID, highlight.ID, localPath)
			pathChan <- localPath
		}(h)
	}

	for i := 0; i < len(highlights); i++ {
		select {
		case err := <-errChan:
			log.Printf("Error occurred during download [userID: %s, error: %v]", payload.UserID, err)
			updateMergedVideoStatus(payload.MergedVideoID, "failed")
			for _, path := range localPaths {
				os.Remove(path) // 清理已下載的檔案
			}
			return err
		case path := <-pathChan:
			localPaths = append(localPaths, path)
		}
	}
	log.Printf("All videos downloaded [userID: %s, totalFiles: %d]", payload.UserID, len(localPaths))

	// Write FFmpeg input file
	f, err := os.Create(tempFile)
	if err != nil {
		log.Printf("Failed to create temporary file [userID: %s, mergedVideoID: %s, error: %v]", payload.UserID, payload.MergedVideoID, err)
		updateMergedVideoStatus(payload.MergedVideoID, "failed")
		return fmt.Errorf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tempFile)

	for _, path := range localPaths {
		f.WriteString(fmt.Sprintf("file '%s'\n", path))
		defer os.Remove(path)
	}
	f.Close()

	// Use FFmpeg to merge videos
	log.Printf("Starting FFmpeg merge [userID: %s]", payload.UserID)
	cmd := exec.Command(
		"ffmpeg",
		"-f", "concat",
		"-safe", "0",
		"-i", tempFile,
		"-c", "copy",
		"-y",
		outputPath,
	)

	if err := cmd.Run(); err != nil {
		log.Printf("FFmpeg merge failed [userID: %s, error: %v]", payload.UserID, err)
		return fmt.Errorf("Failed to merge videos: %v", err)
	}

	// Generate thumbnail
	log.Printf("Generating thumbnail [userID: %s]", payload.UserID)
	thumbnailPath := fmt.Sprintf("uploads/%s.jpg", payload.Name)
	cmd = exec.Command(
		"ffmpeg",
		"-i", outputPath,
		"-ss", "00:00:02",
		"-vframes", "1",
		"-q:v", "2",
		thumbnailPath,
	)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to generate thumbnail [userID: %s, error: %v]", payload.UserID, err)
		updateMergedVideoStatus(payload.MergedVideoID, "failed")
		os.Remove(outputPath)
		return fmt.Errorf("Failed to generate thumbnail: %v", err)
	}

	// Upload to Supabase
	log.Printf("Starting Supabase upload [userID: %s]", payload.UserID)
	if err := uploadToSupabase(SupabaseMergedHighlightsBucket, outputPath, fmt.Sprintf("%s.mov", payload.Name), "video/quicktime"); err != nil {
		log.Printf("Failed to upload merged video [userID: %s, error: %v]", payload.UserID, err)
		updateMergedVideoStatus(payload.MergedVideoID, "failed")
		os.Remove(outputPath)
		os.Remove(thumbnailPath)
		return err
	}
	if err := uploadToSupabase(SupabaseMergedThumbnailsBucket, thumbnailPath, fmt.Sprintf("%s.jpg", payload.Name), "image/jpeg"); err != nil {
		log.Printf("Failed to upload thumbnail [userID: %s, error: %v]", payload.UserID, err)
		updateMergedVideoStatus(payload.MergedVideoID, "failed")
		os.Remove(outputPath)
		os.Remove(thumbnailPath)
		return err
	}

	// Update MergedVideo record
	log.Printf("Updating database record [userID: %s, mergedVideoID: %s]", payload.UserID, payload.MergedVideoID)
	if err := DB.Model(&MergedVideo{}).Where("id = ?", payload.MergedVideoID).Updates(map[string]interface{}{
		"status":     "completed",
		"updated_at": time.Now(),
	}).Error; err != nil {
		log.Printf("Failed to update merged video record [userID: %s, mergedVideoID: %s, error: %v]", payload.UserID, payload.MergedVideoID, err)
		updateMergedVideoStatus(payload.MergedVideoID, "failed")
		return fmt.Errorf("Failed to update merged video record: %v", err)
	}

	// Record association with original highlights
	for _, highlightID := range payload.HighlightIds {
		relation := MergedVideoHighlight{
			MergedVideoID: payload.MergedVideoID,
			HighlightID:   highlightID,
			CreatedAt:     time.Now(),
		}
		if err := DB.Create(&relation).Error; err != nil {
			log.Printf("Failed to record association [userID: %s, mergedVideoID: %s, error: %v]", payload.UserID, payload.MergedVideoID, err)
			updateMergedVideoStatus(payload.MergedVideoID, "failed")
			return fmt.Errorf("Failed to record association: %v", err)
		}
	}

	// Clean up temporary files
	os.Remove(outputPath)
	os.Remove(thumbnailPath)

	log.Printf("Merge task completed [userID: %s, mergedVideoID: %s]", payload.UserID, payload.MergedVideoID)
	return nil
}

// Update MergedVideo status
func updateMergedVideoStatus(mergedVideoID, status string) {
	if err := DB.Model(&MergedVideo{}).Where("id = ?", mergedVideoID).Updates(map[string]interface{}{
		"status":     status,
		"updated_at": time.Now(),
	}).Error; err != nil {
		log.Printf("Failed to update status [mergedVideoID: %s, error: %v]", mergedVideoID, err)
	}
}

// Download and save file from Supabase
func downloadAndSaveFile(bucket, filePath, localDir string) (string, error) {
	log.Printf("Starting file download [bucket: %s, filePath: %s]", bucket, filePath)

	// Initialize Supabase client
	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Printf("Supabase client initialization failed [bucket: %s, filePath: %s, error: %v]", bucket, filePath, err)
		return "", fmt.Errorf("Failed to initialize Supabase client: %v", err)
	}

	log.Printf("Creating signed URL [bucket: %s, filePath: %s]", bucket, filePath)
	signedURLResp, err := supabase.Storage.CreateSignedUrl(bucket, filepath.Base(filePath), 60)
	if err != nil {
		log.Printf("Failed to create signed URL [bucket: %s, filePath: %s, error: %v]", bucket, filePath, err)
		return "", fmt.Errorf("Failed to create signed URL: %v", err)
	}

	log.Printf("Starting file content download [bucket: %s, filePath: %s]", bucket, filePath)
	resp, err := http.Get(signedURLResp.SignedURL)
	if err != nil {
		log.Printf("HTTP request failed [bucket: %s, filePath: %s, error: %v]", bucket, filePath, err)
		return "", fmt.Errorf("Failed to download file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("HTTP response error [bucket: %s, filePath: %s, statusCode: %d]", bucket, filePath, resp.StatusCode)
		return "", fmt.Errorf("Failed to download file: HTTP %d", resp.StatusCode)
	}

	localPath := filepath.Join(localDir, filepath.Base(filePath))
	log.Printf("Preparing to create local file [bucket: %s, filePath: %s, localPath: %s]", bucket, filePath, localPath)

	file, err := os.Create(localPath)
	if err != nil {
		log.Printf("Failed to create local file [bucket: %s, filePath: %s, localPath: %s, error: %v]", bucket, filePath, localPath, err)
		return "", fmt.Errorf("Failed to create local file: %v", err)
	}
	defer file.Close()

	written, err := io.Copy(file, resp.Body)
	if err != nil {
		log.Printf("Failed to write file [bucket: %s, filePath: %s, localPath: %s, error: %v]", bucket, filePath, localPath, err)
		return "", fmt.Errorf("Failed to write file: %v", err)
	}

	log.Printf("File download completed [bucket: %s, filePath: %s, localPath: %s, size: %d bytes]", bucket, filePath, localPath, written)
	return localPath, nil
}

type MergedVideoResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	VideoPath     string  `json:"video_path"`
	ThumbnailPath string  `json:"thumbnail_path"`
	Description   *string `json:"description"`
	Status        string  `json:"status"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type PaginatedMergedVideosResponse struct {
	MergedVideos []MergedVideoResponse `json:"merged_videos"`
	TotalCount   int64                 `json:"total_count"` // 總記錄數
	Page         int                   `json:"page"`        // 當前頁碼
	Limit        int                   `json:"limit"`       // 每頁數量
}

func listUserMergedVideosHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)
	if userID == "" {
		log.Printf("Unauthorized request [userID empty]")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	supabase, err := supabase.NewClient(SupabaseURL, SupabaseAPIKey, &supabase.ClientOptions{})
	if err != nil {
		log.Printf("Failed to initialize Supabase client [userID: %s, error: %v]", userID, err)
		http.Error(w, "Error initializing client", http.StatusInternalServerError)
		return
	}

	// Get pagination parameters
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	// Set default values
	page := 1
	limit := 10
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 { // 限制最大 limit 為 100
			limit = l
		}
	}

	// Calculate offset
	offset := (page - 1) * limit

	// Query total count
	var totalCount int64
	if err := DB.Model(&MergedVideo{}).Where("user_id = ?", userID).Count(&totalCount).Error; err != nil {
		log.Printf("Failed to count merged videos [userID: %s, error: %v]", userID, err)
		http.Error(w, "Error counting merged videos", http.StatusInternalServerError)
		return
	}

	// Query user's merged videos (pagination)
	var mergedVideos []MergedVideo
	if err := DB.Where("user_id = ?", userID).
		Offset(offset).
		Limit(limit).
		Order("created_at DESC"). // Optional: Sort by creation time in descending order
		Find(&mergedVideos).Error; err != nil {
		log.Printf("Failed to query merged videos [userID: %s, error: %v]", userID, err)
		http.Error(w, "Error querying merged videos", http.StatusInternalServerError)
		return
	}

	// Format response
	var response []MergedVideoResponse
	for _, mv := range mergedVideos {
		videoSignedURL, err := supabase.Storage.CreateSignedUrl(SupabaseMergedHighlightsBucket, filepath.Base(mv.VideoPath), 86400)
		if err != nil {
			log.Printf("Failed to create video signed URL [userID: %s, error: %v]", userID, err)
			http.Error(w, "Error generating signed URL", http.StatusInternalServerError)
			return
		}
		thumbnailSignedURL, err := supabase.Storage.CreateSignedUrl(SupabaseMergedThumbnailsBucket, filepath.Base(mv.ThumbnailPath), 86400)
		if err != nil {
			log.Printf("Failed to create thumbnail signed URL [userID: %s, error: %v]", userID, err)
			http.Error(w, "Error generating signed URL", http.StatusInternalServerError)
			return
		}
		response = append(response, MergedVideoResponse{
			ID:            mv.ID,
			Name:          mv.Name,
			VideoPath:     videoSignedURL.SignedURL,
			ThumbnailPath: thumbnailSignedURL.SignedURL,
			Description:   mv.Description,
			Status:        mv.Status,
			CreatedAt:     mv.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     mv.UpdatedAt.Format(time.RFC3339),
		})
	}

	// Build paginated response
	paginatedResponse := PaginatedMergedVideosResponse{
		MergedVideos: response,
		TotalCount:   totalCount,
		Page:         page,
		Limit:        limit,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(paginatedResponse); err != nil {
		log.Printf("Failed to encode response [userID: %s, error: %v]", userID, err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully retrieved merged videos [userID: %s, page: %d, limit: %d, total: %d]", userID, page, limit, totalCount)
}

func main() {
	router := mux.NewRouter()

	router.Use(corsMiddleware)
	router.Use(loggingMiddleware)

	protectedRoutes := router.PathPrefix("/").Subrouter()
	protectedRoutes.Use(jwtMiddleware)

	// Existing routes
	protectedRoutes.HandleFunc("/api/user", getCurrentUserHandler).Methods("GET", "OPTIONS")
	protectedRoutes.HandleFunc("/upload", uploadFileHandler).Methods("POST", "OPTIONS")
	protectedRoutes.HandleFunc("/thumbnails", listThumbnailsHandler).Methods("GET", "OPTIONS")
	protectedRoutes.HandleFunc("/video/{videoID}", deleteFileHandler).Methods("DELETE", "OPTIONS")
	protectedRoutes.HandleFunc("/video/{videoID}/highlights", getVideoHighlightsHandler).Methods("GET", "OPTIONS")
	protectedRoutes.HandleFunc("/api/highlights/merge", mergeHighlightsHandler).Methods("POST", "OPTIONS")
	protectedRoutes.HandleFunc("/user/merged-videos", listUserMergedVideosHandler).Methods("GET", "OPTIONS")

	router.HandleFunc("/asset/logo", logoHandler).Methods("GET")
	router.HandleFunc("/auth/google/login", loginHandler).Methods("GET")
	router.HandleFunc("/auth/google/callback", callbackHandler).Methods("GET")

	mux := asynq.NewServeMux()
	mux.HandleFunc("merge_highlights", handleMergeTask)
	go func() {
		if err := taskServer.Run(mux); err != nil {
			log.Fatalf("Failed to start task processor: %v", err)
		}
	}()

	fmt.Printf("Server running at http://0.0.0.0:%s\n", Port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+Port, router))
}
