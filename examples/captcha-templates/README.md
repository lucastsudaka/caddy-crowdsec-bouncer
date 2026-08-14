# CAPTCHA templates

The embedded default template submits every proof automatically after the provider reports a successful challenge. If the server rejects a proof, the refreshed challenge uses the same automatic flow. `manual.html` is an alternative that always waits for the visitor to select **Continue**.

Configure the manual template with an absolute path:

```caddyfile
crowdsec {
    captcha_template_path /etc/caddy/captcha/manual.html
}
```

Both templates require the provider's JavaScript. The manual button replaces automatic submission; it does not provide a JavaScript-free CAPTCHA flow.

Custom templates use Go `html/template` syntax and receive `.Provider`, `.SiteKey`, `.ScriptURL`, `.WidgetClass`, `.Action`, `.FormAction`, `.Nonce`, and `.Failed`. Keep the form method as `post`, use `.FormAction` as its action, and preserve the provider widget attributes. Add `nonce="{{.Nonce}}"` to trusted inline scripts. The response Content Security Policy intentionally blocks inline scripts without this nonce and external resources other than the selected CAPTCHA provider.
