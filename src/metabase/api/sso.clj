(ns metabase.api.sso
  "`/auth/sso` Routes.

  Implements the SSO routes needed for SAML and JWT. This namespace primarily provides hooks for those two backends so
  we can have a uniform interface both via the API and code"
  (:require
   [compojure.core :refer [GET POST PUT]]
   [metabase.integrations.sso.interface :as sso.i]
   [metabase.integrations.jwt]
   [metabase.integrations.saml]
   [metabase.integrations.sso-settings :as sso-settings]
   [metabase.api.common :as api]
   [metabase.util :as u]
   [metabase.util.i18n :refer [trs tru]]
   [metabase.util.log :as log]
   [stencil.core :as stencil]
   [metabase.models.setting :as setting]
   [schema.core :as s]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

;; load the SSO integrations so their implementations for the multimethods below are available.
(comment metabase.integrations.jwt/keep-me
         metabase.integrations.saml/keep-me)

#_{:clj-kondo/ignore [:deprecated-var]}
(api/defendpoint-schema GET "/"
  "SSO entry-point for an SSO user that has not logged in yet"
  [:as req]
  (try
    (sso.i/sso-get req)
    (catch Throwable e
      (log/error #_e (trs "Error returning SSO entry point"))
      (throw e))))

(defn- sso-error-page [^Throwable e]
  {:status  (get (ex-data e) :status-code 500)
   :headers {"Content-Type" "text/html"}
   :body    (stencil/render-file "metabase_enterprise/sandbox/api/error_page"
              (let [message    (.getMessage e)
                    data       (u/pprint-to-str (ex-data e))]
                {:errorMessage   message
                 :exceptionClass (.getName Exception)
                 :additionalData data}))})

#_{:clj-kondo/ignore [:deprecated-var]}
(api/defendpoint-schema POST "/"
  "Route the SSO backends call with successful login details"
  [:as req]
  (try
    (sso.i/sso-post req)
    (catch Throwable e
      (log/error e (trs "Error logging in"))
      (sso-error-page e))))

#_{:clj-kondo/ignore [:deprecated-var]}
(api/defendpoint-schema PUT "/settings"
  "Update SAML Sign-In related settings. You must be a superuser or have `setting` permission to do this."
  [:as {{:keys [saml-identity-provider-uri saml-enabled saml-identity-provider-issuer saml-identity-provider-certificate saml-application-name saml-attribute-email saml-attribute-firstname saml-attribute-lastname]} :body}]
  {saml-identity-provider-uri                   (s/maybe s/Str)
   saml-enabled                                 (s/maybe s/Bool)
   saml-identity-provider-issuer                (s/maybe s/Str)
   saml-identity-provider-certificate           (s/maybe s/Str)
   saml-application-name                        (s/maybe s/Str)
   saml-attribute-email                         (s/maybe s/Str)
   saml-attribute-firstname                     (s/maybe s/Str)
   saml-attribute-lastname                      (s/maybe s/Str)
   enable-password-login                        (s/maybe s/Bool)}
  (api/check-superuser)
  ;; Set saml-enabled in a separate step
  (t2/with-transaction [_conn]
   (setting/set-many! {:saml-identity-provider-uri                   saml-identity-provider-uri
                       :saml-identity-provider-issuer                saml-identity-provider-issuer
                       :saml-identity-provider-certificate           saml-identity-provider-certificate
                       :saml-application-name                        saml-application-name
                       :saml-attribute-email                         saml-attribute-email
                       :saml-attribute-firstname                     saml-attribute-firstname
                       :saml-attribute-lastname                      saml-attribute-lastname
                       :enable-password-login                        enable-password-login})
   (sso-settings/saml-enabled! saml-enabled)))

(api/define-routes)
