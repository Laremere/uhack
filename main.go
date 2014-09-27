package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var root = "https://vps.redig.us"

var db *sql.DB

func main() {
	log.Println("Starting server")

	var err error
	db, err = sql.Open("mysql", "uhack:@/uhack")
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/register/", simplePage("register"))
	http.HandleFunc("/login/", simplePage("login"))
	http.HandleFunc("/about/", simplePage("about"))
	http.HandleFunc("/recipes/", recipesHandler)
	http.HandleFunc("/registercallback/", registerHandler)
	http.HandleFunc("/logincallback/", loginHandler)
	http.HandleFunc("/search/", searchHandler)
	http.HandleFunc("/recipe/", recipeHandler)
	http.HandleFunc("/made/", madeHandler)
	http.HandleFunc("/badges/", badgesHandler)
	http.HandleFunc("/", simplePage("home"))
	//http.HandleFunc("/", indexHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	//Redirect http to https
	go func() {
		log.Fatal(http.ListenAndServe(":8080",
			http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, root+r.RequestURI, http.StatusMovedPermanently)
				})))
	}()

	//Serve https
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}

func simplePage(fileName string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tem, err := template.ParseFiles("html/"+fileName+".html", "html/defines.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = tem.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func authenticate(r *http.Request) (uid int) {
	authCookie, err := r.Cookie("authtoken")
	if err != nil {
		return 0
	}

	authToken := authCookie.Value
	underscorePos := 0
	for ; underscorePos < len(authToken); underscorePos++ {
		if authToken[underscorePos] == '_' {
			break
		}
	}

	var tempUid int64
	tempUid, err = strconv.ParseInt(authToken[0:underscorePos], 10, 64)
	if err != nil {
		log.Println(err)
		return 0
	}
	uid = int(tempUid)

	authToken = authToken[underscorePos+1:]
	var correctToken string
	err = db.QueryRow("SELECT authtoken FROM Users WHERE uid=?", uid).Scan(&correctToken)
	if err != nil {
		log.Println(err)
		return 0
	}

	if authToken != correctToken {
		return 0
	}

	return
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.PostForm.Get("username")
	email := r.PostForm.Get("email")

	var count int

	err = db.QueryRow("SELECT COUNT(*) FROM Users WHERE Username=? OR Email=?", username, email).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count > 0 {
		http.Error(w, "Username or email already in use", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO Users (Username, Email) VALUES (?,?)", username, email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	loginHandler(w, r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.PostForm.Get("username")
	var uid int
	err = db.QueryRow("SELECT UID FROM Users WHERE UPPER(Username)=UPPER(?)", username).Scan(&uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if uid <= 0 {
		http.Error(w, "invalid user id", http.StatusInternalServerError)
		return
	}

	var authtoken string
	{
		var buffer bytes.Buffer
		encoder := base32.NewEncoder(base32.StdEncoding, &buffer)
		_, err = io.CopyN(encoder, rand.Reader, 20)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = encoder.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		authtoken = string(buffer.Bytes())
	}

	_, err = db.Exec("UPDATE Users SET authtoken=? WHERE UID=?", authtoken, uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authtoken = strconv.FormatInt(int64(uid), 10) + "_" + authtoken

	expire := time.Now().AddDate(0, 0, 7)
	const cookieName = "authtoken"
	cookie := http.Cookie{
		Name:       cookieName,
		Value:      authtoken,
		Path:       "/",
		Domain:     "vps.redig.us",
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     60 * 60 * 24 * 7,
		Secure:     false,
		HttpOnly:   false,
		Raw:        cookieName + "=" + authtoken,
		Unparsed:   []string{cookieName + "=" + authtoken},
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "https://vps.redig.us", 303)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, authenticate(r))
}

func ApiCall(url string, structure interface{}) error {
	ApiResp, err := http.Get(url)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(ApiResp.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, structure)
}

type RecipeSearchResults struct {
	Results []*RecipeSearchResult
}

type RecipeSearchResult struct {
	Name           string
	Id             string
	Url            string
	Cuisine        string
	Cooking_Method string
	Ingredients    []string
	Image          string
	Thumb          string
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	params := make([]string, 0)
	if value := r.Form.Get("recipeName"); value != "" {
		params = append(params, "name-contains="+value)
	}
	if value := r.Form.Get("ingredients"); value != "" {
		params = append(params, "ingredients-any="+value)
	}
	if value := r.Form.Get("cuisine"); value != "" {
		params = append(params, "cuisine="+value)
	}
	if value := r.Form.Get("method"); value != "" {
		params = append(params, "method="+value)
	}
	if value := r.Form.Get("offset"); value != "" {
		params = append(params, "offset="+value)
	}
	params = append(params, "limit=20")

	url := "http://api.pearson.com:80/kitchen-manager/v1/recipes?" + strings.Join(params, "&")
	var result RecipeSearchResults

	err = ApiCall(url, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tem, err := template.ParseFiles("html/search.html", "html/defines.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tem.Execute(w, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type RecipeDetail struct {
	Auth           bool
	Name           string
	Id             string
	Image          string
	Thumb          string
	Cuisine        string
	Cooking_Method string
	Serves         float64
	Yields         string
	Ingredients    []*IngredientDetail
	Directions     []string
}

type IngredientDetail struct {
	Name        string
	Id          string
	Quantity    string
	Unit        string
	Preparation string
}

var AsciiFilter = regexp.MustCompile("[^A-Za-z0-9 [:punct:]]")

func recipeHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	url := "https://api.pearson.com/kitchen-manager/v1/recipes/" + r.Form.Get("id")

	var result RecipeDetail
	err = ApiCall(url, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for i := range result.Directions {
		result.Directions[i] = AsciiFilter.ReplaceAllString(result.Directions[i], "")
	}

	tem, err := template.ParseFiles("html/singleRecipe.html", "html/defines.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result.Auth = authenticate(r) != 0
	err = tem.Execute(w, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func madeHandler(w http.ResponseWriter, r *http.Request) {
	uid := authenticate(r)
	if uid == 0 {
		http.Error(w, "Not logged in", http.StatusInternalServerError)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rid := r.Form.Get("id")

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM UsersRecipes WHERE UID=? AND RID=?", uid, rid).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count > 0 {
		http.Redirect(w, r, "https://vps.redig.us/recipe/?id="+rid, 303)
		return
	}

	_, err = db.Exec("INSERT INTO UsersRecipes (UID, RID) VALUES ( ? , ? )", uid, rid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

type BadgesPage struct {
	Auth   bool
	Badges []*Badge
}

type Badge struct {
	Name        string
	Description string
	ReqCount    int64
	Progress    int64
}

func badgesHandler(w http.ResponseWriter, r *http.Request) {
	var result BadgesPage

	uid := authenticate(r)
	result.Auth = uid != 0

	if result.Auth {

		rows, err := db.Query(`SELECT 
		Badges.Name, Badges.Description, Badges.RequiredCount, UB.Progress 
		FROM Badges 
		LEFT OUTER JOIN 
			( SELECT Progress, BID
				FROM UsersBadges 
				WHERE UsersBadges.UID=?
				) AS UB
		ON UB.BID = Badges.ID 
		`, uid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		result.Badges = make([]*Badge, 0)
		for rows.Next() {
			var b Badge
			var progress sql.NullInt64
			err = rows.Scan(&b.Name, &b.Description, &b.ReqCount, &progress)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if progress.Valid {
				b.Progress = progress.Int64
				if b.Progress > b.ReqCount {
					b.Progress = b.ReqCount
				}
			} else {
				b.Progress = 0
			}
			result.Badges = append(result.Badges, &b)
		}
	}

	tem, err := template.ParseFiles("html/badges.html", "html/defines.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tem.Execute(w, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func recipesHandler(w http.ResponseWriter, r *http.Request) {
	type Cuisines struct {
	}

	type CuisinesResponse struct {
	}

	url := "http://api.pearson.com:80/kitchen-manager/v1/cuisines?limit=10000"
	var result RecipeSearchResults

	err = ApiCall(url, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tem, err := template.ParseFiles("html/search.html", "html/defines.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tem.Execute(w, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}
