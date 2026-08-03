import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { BrowserRouter } from "react-router-dom";
import { GoogleReCaptchaProvider } from "react-google-recaptcha-v3";
import "./index.css";

const recaptchaEnabled = import.meta.env.VITE_RECAPTCHA_ENABLED === 'true';

ReactDOM.createRoot(document.getElementById("root")).render(
  <>
    {recaptchaEnabled ? (
      <GoogleReCaptchaProvider reCaptchaKey={import.meta.env.VITE_RECAPTCHA_SITE_KEY}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </GoogleReCaptchaProvider>
    ) : (
      <BrowserRouter>
        <App />
      </BrowserRouter>
    )}
  </>
);
