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

// TODO: Do not use global variable here. Should use repository pattern
var db *gorm.DB

func getIPAddress(c *gin.Context) string {
	ip := c.GetHeader("X-Real-IP")
	if ip == "" {
		ip = c.ClientIP()
	}
	return ip
}

func getUserByUsername(u string) (user, error) {
	var userFound user

	if result := db.First(&userFound, user{Username: u}, "Username"); result.Error != nil {
		return user{}, result.Error
	}
	return userFound, nil
}

func updateIPByUsername(u string, ip string) error {
	var userFound user

	if result := db.Model(&userFound).Where(user{Username: u}).Updates(user{IP: ip}); result.Error != nil {
		return result.Error
	}
	return nil
}

// TODO: Add tests for these functions
func getUsers(c *gin.Context) {
	var users []user

	if result := db.Find(&users); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "something went wrong. please contact administrator.",
			"error":   result.Error.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, users)
}

func createUser(c *gin.Context) {
	var newUser user

	if err := c.BindJSON(&newUser); err != nil {
		fmt.Println("Error while adding user", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid data",
			"error":   err.Error(),
		})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
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
			"error":   result.Error.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user created"})
}

func updateUserIP(c *gin.Context) {
	var request user

	if err := c.BindJSON(&request); err != nil {
		fmt.Println("Error while updating IP", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request",
			"error":   err.Error(),
		})
		return
	}

	foundUser, err := getUserByUsername(request.Username)
	if err != nil {
		fmt.Println("Error while finding user", err)
		msg := "something went wrong. please contact administrator."
		s := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			msg = "could not find the user"
			s = http.StatusNotFound
		}
		c.JSON(s, gin.H{
			"message": msg,
			"error":   err.Error(),
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(request.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid password",
		})
		return
	}

	if err := updateIPByUsername(request.Username, getIPAddress(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "something went wrong. please contact administrator",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusNoContent, gin.H{"message": "IP address updated"})
}

func main() {
	// Initialize and connect to sqlite file
	var err error
	db, err = gorm.Open(sqlite.Open("peeps.db"), &gorm.Config{TranslateError: true})
	if err != nil {
		panic("failed to connect to db")
	}
	db.AutoMigrate(&user{})

	router := gin.Default()
	router.GET("/users", getUsers)
	router.POST("/users", createUser)
	router.POST("/users/ip", updateUserIP)

	// This is set according to my home router configuration
	// TODO: Need to change this when deploying to prod
	router.SetTrustedProxies([]string{"192.168.0.0/16"})
	router.Run("0.0.0.0:8080") // This is meant to be run with a reverse proxy like nginx
}
