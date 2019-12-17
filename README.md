# dggoauth

this package implements the oauth flow from [here](https://github.com/destinygg/website/blob/master/OAUTH.md)

## Example

```go
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tensei/dggoauth"
)

func main() {

    // ClientID and ClientSecret from here
    // https://www.destiny.gg/profile/developer
    dgg, err := dggoauth.NewClient(&dggoauth.Options{
        ClientID:     "xxxxxxxxxxxxxxxx", // required
        ClientSecret: "xxxxxxxxxxxxxxxx", // required
        RedirectURI:  "https://linktomysites/callback", // required
    })
    if err != nil {
        panic(err)
    }

    stateVerifierStore := make(map[string]string)

    r := gin.Default()
    r.GET("/login", func(c *gin.Context) {
        state := "randomlyGeneratedState"
        redirectURL, verifier := dgg.GetAuthorizationURL(state)

        // store state and verifier together
        stateVerifierStore[state] = verifier

        // redirect the user to the redirectURL
        c.Redirect(http.StatusFound, redirectURL)
    })

    // after they login they get sent back to your redirect URL
    r.GET("/callback", func(c *gin.Context) {
        // same state you provided above
        state := c.Query("state")
        code := c.Query("code")

        // get your verifier from the store
        verifier := stateVerifierStore[state]

        // get the access token
        at, err := dgg.GetAccessToken(code, verifier)
        if err != nil {
            panic(err)
        }

        // get userinfo with access token or whatever

        c.Redirect(http.StatusFound, "/")
    })
    r.Run()
}
```
