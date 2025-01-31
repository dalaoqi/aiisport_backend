package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	supa "github.com/nedpals/supabase-go"
)

var (
	SupabaseBucket  string
	SupabaseURL     string
	SupabaseAPIKey  string
	StorageEndpoint = "/storage/v1/object"
)

func init() {
	// 讀取 .env 檔案
	if err := godotenv.Load(); err != nil {
		log.Println("未找到 .env 檔案，將嘗試使用系統環境變數")
	}

	// 從環境變數中讀取必要設定
	SupabaseBucket = os.Getenv("SUPABASE_BUCKET")
	SupabaseURL = os.Getenv("SUPABASE_URL")
	SupabaseAPIKey = os.Getenv("SUPABASE_API_KEY")

	// 檢查必要環境變數是否存在
	requiredEnv := []string{"SUPABASE_BUCKET", "SUPABASE_URL", "SUPABASE_API_KEY"}
	for _, env := range requiredEnv {
		if os.Getenv(env) == "" {
			log.Fatalf("環境變數 %s 未設定", env)
		}
	}
}

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20) // 10 MB 限制
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

	buffer := bytes.NewBuffer(nil)
	if _, err := buffer.ReadFrom(file); err != nil {
		http.Error(w, "Error reading the file", http.StatusInternalServerError)
		return
	}

	fileName := filepath.Base(handler.Filename)
	uploadURL := fmt.Sprintf("%s%s/%s/%s", SupabaseURL, StorageEndpoint, SupabaseBucket, fileName)

	req, err := http.NewRequest("POST", uploadURL, buffer)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", "Bearer "+SupabaseAPIKey)
	req.Header.Set("Content-Type", handler.Header.Get("Content-Type"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error uploading to Supabase", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		http.Error(w, string(body), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("File uploaded successfully: %s", fileName)))
}

func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	supabase := supa.CreateClient(SupabaseURL, SupabaseAPIKey)

	files := supabase.Storage.From(SupabaseBucket).List("", supa.FileSearchOptions{})

	for _, file := range files {
		fmt.Fprintf(w, "%s\n", file.Name)
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/upload", uploadFileHandler).Methods("POST")
	router.HandleFunc("/list", listFilesHandler).Methods("GET")

	port := ":8080"
	fmt.Printf("Server running at http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, router))
}
