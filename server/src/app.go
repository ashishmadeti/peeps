package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type user struct {
	gorm.Model
	Username string `json:"username" binding:"required" gorm:"<-:create;unique;not null"`
	Password string `json:"password" binding:"required,max=72" gorm:"not null"`
	IP       string `gorm:"not null"`
}

// TODO: Do not use global variable here
var db *gorm.DB


func getIPAddress(c *gin.Context) string {
	ip := c.GetHeader("X-Real-IP")
	if ip == "" {
		ip = c.ClientIP()
	}
	return ip
}

// TODO: Add tests for these functions
func getUsers(c *gin.Context) {
	var users []user

	if result := db.Find(&users); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "something went wrong. please contact administrator.",
			"error": result.Error.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, users)
}

func createUser(c *gin.Context) {
	var newUser user

	if err := c.BindJSON(&newUser); err != nil {
		fmt.Println("Error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid data",
			"error": err.Error(),
		})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(newUser.Password), 0)
	newUser.Password = string(hash)
	newUser.IP = getIPAddress(c)

	if result := db.Create(&newUser); result.Error != nil {
		msg := "something went wrong. please contact administrator."
		s := http.StatusInternalServerError
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			msg = "username already exists"
			s = http.StatusBadRequest
		}
		c.JSON(s, gin.H{
			"message": msg,
			"error": result.Error.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user created"})
}

// TODO: Allow user to update IP address, provided correct password
// Use bcrypt.CompareHashAndPassword() for checking if password is correct

func main() {
	// Initialize and connect to sqlite file
	var err error
	db, err = gorm.Open(sqlite.Open("peeps.db"), &gorm.Config{TranslateError: true})
	if err != nil {
		panic("failed to connect to db")
	}
	db.AutoMigrate(&user{})

	router := gin.Default()
	router.POST("/users", createUser)
	router.GET("/users", getUsers)

	// This is set according to my home router configuration
	// TODO: Need to change this when deploying to prod
	router.SetTrustedProxies([]string{"192.168.0.0/16"})
	router.Run("0.0.0.0:8080") // This is meant to be run with a reverse proxy like nginx

}
