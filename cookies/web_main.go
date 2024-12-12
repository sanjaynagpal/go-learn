package main

import (
	"log"

	webview "github.com/webview/webview_go"
)

func main() {
	debug := true
	w := webview.New(debug)
	defer w.Destroy()
	w.setTitle("Just Testing Webview")
	w.setSize(800, 600, webview.HintNone)
	w.Navigate("https://developer.android.com/reference/android/webkit/CookieManager")

	// function that will be executed after the page is loaded
	w.Dispatch(func() {
		// JavaScript code to get cookies
		cookieJs := `
	(function() {
	    return document.cookie;
	})();
		`
		// Evaluate the JavaScript code
		w.Bind("getCookie", func() string {
			return w.Eval(cookieJs)
		})
		cookies := w.Eval(cookieJs)
		log.Printf("Cookies: %s\n", cookies)
	})
	w.Run()
}
