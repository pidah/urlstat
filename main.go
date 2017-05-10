package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pidah/urlstat/stat"
)

var DB = make(map[string]string)

func main() {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{})
	})

	r.GET("/trace", handlePanic, func(c *gin.Context) {
		url := c.Query("url")

		resp := stat.Trace(stat.NewRequest(url))
		c.JSON(200, gin.H{
			"status": "ok",
			"trace":  resp.String(),
		})
	})

	r.StaticFS("/static", http.Dir("static"))

	r.Run(":" + os.Getenv("PORT"))
}

func handlePanic(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			c.JSON(200, gin.H{
				"status":  "err",
				"message": err,
			})
		}
	}()

	c.Next()
}
