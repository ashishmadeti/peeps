package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,max=72"`
	IP       string
}

var users []user

func getIPAddress(c *gin.Context) string {
	ip := c.GetHeader("X-Real-IP")
	if ip == "" {
		ip = c.ClientIP()
	}
	return ip
}

func getUsers(c *gin.Context) {
	c.JSON(http.StatusOK, users)
}

func createUser(c *gin.Context) {
	var newUser user

	if err := c.BindJSON(&newUser); err != nil {
		fmt.Println("Error", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid data"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(newUser.Password), 0)
	newUser.Password = string(hash)
	newUser.IP = getIPAddress(c)
	users = append(users, newUser)

	c.JSON(http.StatusCreated, gin.H{"message": "user created"})
}

// TODO: Save users in sqlite

// TODO: Allow user to update IP address, provided correct password
// Use bcrypt.CompareHashAndPassword() for checking if password is correct

func main() {
	router := gin.Default()
	users = make([]user, 0) // Initialize users to empty array
	router.POST("/users", createUser)
	router.GET("/users", getUsers)

	// This is set according to my home router configuration
	// TODO: Need to change this when deploying to prod
	router.SetTrustedProxies([]string{"192.168.0.0/16"})
	router.Run("0.0.0.0:8080") // This is meant to be run with a reverse proxy like nginx

}
