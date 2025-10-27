package main

import (
	"fmt"

	"github.com/leaanthony/clir"
	"github.com/sanjaynagpal/go-learn/waverly/app-auth-client/cmd/auth/commands"
	"github.com/sanjaynagpal/go-learn/waverly/app-auth-client/color"
)

func main() {
	app := clir.NewCli("auth", "Waverly Auth Client", "v1.0.0")
	app.SetBannerFunction(func(c *clir.Cli) string {
		return fmt.Sprintf("%s %s", color.Green("EntraID authentication app"), color.DarkRed(app.Version()))
	})
	defer printFooter()

	app.NewSubCommandFunction("client", "Waverly client app", authAppFn)

	err := app.Run()
	if err != nil {
		fmt.Println("Error:", err)
	}
}

func printFooter() {
	fmt.Println(color.Cyan("Thank you for using Waverly Auth Client!"))
}

func authAppFn(f *commands.AuthCommand) error {
	// Set color preference
	color.ColorEnabled = !f.NoColor
	return commands.AuthApp(f)
}
