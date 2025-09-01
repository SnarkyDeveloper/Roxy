package helpers

import (
	"math/rand"
	"regexp"
	"roxy/server/config"
	"roxy/server/user"
	"strconv"
	"time"
)

func extractPlaceholders(path string) []string {
	re := regexp.MustCompile(`\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(path, -1)
	var result []string
	for _, match := range matches {
		if len(match) > 1 {
			result = append(result, match[1])
		}
	}
	return result
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano())) // Seed the random number generator
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func CreatePath(config *config.Config, user user.User, repo config.Repo) string {
	path := config.Path
	placeholders := extractPlaceholders(path)
	for _, placeholder := range placeholders {
		var replacement string
		switch placeholder {
		case "username":
			replacement = user.Username
		case "user":
			replacement = user.UserID
		case "random:":
			len, err := strconv.Atoi(placeholder[len("random:"):])
			if err != nil {
				len = 16
			}
			replacement = generateRandomString(len)
		case "repo":
			replacement = repo.Name
		case "repo_id":
			replacement = repo.ID
		default:
			replacement = ""
		}
		path = regexp.MustCompile(`\{`+placeholder+`\}`).ReplaceAllString(path, replacement)
	}
	return path // example: /{username}/{repo} -> /snarky/roxy
}

func CurrentMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
