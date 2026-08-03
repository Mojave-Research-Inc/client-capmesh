# Google OAuth 2.0 Sign-in Setup for Capmesh

This guide walks through configuring Google OAuth 2.0 for capmesh using the Google Cloud Console project.

## Prerequisites

- Access to Google Cloud Console
- SSH access to capmesh host
- Ability to modify OpenBao secrets (`asg/services/capmesh-google`)
- Admin access to the capmesh deployment

## Step 1: Create or Select an OAuth 2.0 Web Client

### In Google Cloud Console

1. Navigate to **APIs & Services** → **Credentials**
2. Click **+ Create Credentials** → **OAuth client ID**
3. If prompted, configure the OAuth consent screen first (see Step 3 below)
4. Select Application Type: **Web application**
5. Enter a name (e.g., `Capmesh Google Sign-in`)
6. Under **Authorized redirect URIs**, click **+ Add URI** and enter:
   ```
   https://capmesh.example.local/api/v1/auth/google/callback
   ```
7. Click **Create**

### Save the Credentials

On the confirmation dialog, you will see:
- **Client ID**: A string ending in `.apps.googleusercontent.com`
- **Client Secret**: A private key (save this securely — it will not be shown again)

Do NOT close this dialog until you have saved both values securely.

## Step 2: Verify Redirect URI Configuration

The redirect URI must match exactly in both places:

**Google Cloud Console:**
- `https://capmesh.example.local/api/v1/auth/google/callback`

**Capmesh Environment (.env or OpenBao):**
- `CAPMESH_GOOGLE_REDIRECT_URI=https://capmesh.example.local/api/v1/auth/google/callback`

If these do not match, the OAuth callback will fail with a `redirect_uri_mismatch` error.

## Step 3: Configure OAuth Consent Screen

The OAuth consent screen determines who can sign in and what permissions they grant.

### Access the Consent Screen

1. In Google Cloud Console, navigate to **APIs & Services** → **OAuth consent screen**
2. Select **User Type: External** (required for production testing without verification)
3. Click **Create**

### Configure Basic Application Information

1. **App name:** `Capmesh`
2. **User support email:** admin@example.com
3. **Developer contact information:** admin@example.com
4. Click **Save and Continue**

### Configure Scopes

1. On the "Scopes" step, click **Add or Remove Scopes**
2. Search for and select:
   - `openid`
   - `email`
   - `profile`
3. Click **Update** then **Save and Continue**

### Add Test Users (OAuth Consent Screen Testing)

This step is critical for restricting sign-in to specific Gmail addresses.

1. On the "Test users" step, click **+ Add Users**
2. For each authorized user, enter their email address:
   ```
   admin@example.com
   ```
3. Click **Add** for each user
4. Click **Save and Continue**
5. Review the summary and click **Back to Dashboard**

The app is now in **Testing** status with explicitly defined test users.

## Step 4: Store Credentials in OpenBao

The Client Secret must never be committed to source control. Store it in OpenBao.

### Store in OpenBao

```bash
# SSH to a machine with OpenBao access (or use bao-client locally)
secret-manager put <path>/capmesh-google \
  client_id="<CLIENT_ID_FROM_GCP>.apps.googleusercontent.com" \
  web_client_secret="<CLIENT_SECRET_FROM_GCP>"
```

Or, if using the raw OpenBao API:

```bash
secret-manager put <path>/capmesh-google \
  client_id="<CLIENT_ID_FROM_GCP>.apps.googleusercontent.com" \
  web_client_secret="<CLIENT_SECRET_FROM_GCP>"
```

### Verify Storage

```bash
secret-manager get <path>/capmesh-google
```

You should see both `client_id` and `web_client_secret` keys.

## Step 5: Set Environment Variables on Capmesh Host

The capmesh host reads the following environment variables at startup:

```bash
CAPMESH_GOOGLE_CLIENT_ID=<value from OpenBao>
CAPMESH_GOOGLE_CLIENT_SECRET=<value from OpenBao>
CAPMESH_GOOGLE_REDIRECT_URI=https://capmesh.example.local/api/v1/auth/google/callback
CAPMESH_GOOGLE_ALLOWED_EMAILS=admin@example.com
```

### Inject via systemd (Recommended)

If capmesh runs under systemd, edit the service file to source the secrets:

```bash
sudo systemctl edit capmesh.service
```

Add an `EnvironmentFile` directive pointing to a secrets file:

```ini
[Service]
EnvironmentFile=/etc/capmesh/google-secrets.env
ExecStart=/path/to/capmesh
```

Create `/etc/capmesh/google-secrets.env` (mode 0600, owner root:root):

```bash
CAPMESH_GOOGLE_CLIENT_ID=<from OpenBao>
CAPMESH_GOOGLE_CLIENT_SECRET=<from OpenBao>
CAPMESH_GOOGLE_REDIRECT_URI=https://capmesh.example.local/api/v1/auth/google/callback
CAPMESH_GOOGLE_ALLOWED_EMAILS=admin@example.com
```

Restart the service:

```bash
sudo systemctl restart capmesh
```

### Inject via Deployment (Docker / Podman)

If capmesh runs containerized, inject secrets at container startup:

```bash
podman run \
  -e CAPMESH_GOOGLE_CLIENT_ID="$(secret-manager get <path>/capmesh-google client_id)" \
  -e CAPMESH_GOOGLE_CLIENT_SECRET="$(secret-manager get <path>/capmesh-google web_client_secret)" \
  -e CAPMESH_GOOGLE_REDIRECT_URI="https://capmesh.example.local/api/v1/auth/google/callback" \
  -e CAPMESH_GOOGLE_ALLOWED_EMAILS="admin@example.com" \
  capmesh:latest
```

## Step 6: Test the Google Sign-in Flow

1. Navigate to `https://capmesh.example.local/api/v1/auth/google/callback` (or the capmesh login page)
2. Click **Sign in with Google**
3. You will be redirected to Google's login screen
4. Sign in with an authorized test user account (e.g., admin@example.com)
5. Google will prompt for consent to share email and profile information
6. After granting consent, you will be redirected back to capmesh

If you receive a `redirect_uri_mismatch` or `invalid_client` error, verify Step 2 (redirect URI) and Step 5 (environment variables).

## Adding or Removing Authorized Users

### Add a New User

To allow a new user to sign in, you must:

1. **Add as a Test User in Google Cloud Console**
   - Navigate to **APIs & Services** → **OAuth consent screen**
   - Scroll to **Test users**
   - Click **+ Add Users**
   - Enter the user's Gmail address
   - Click **Add**

2. **Update CAPMESH_GOOGLE_ALLOWED_EMAILS Environment Variable**
   - SSH to the capmesh host
   - Update `/etc/capmesh/google-secrets.env` (or equivalent secrets file):
     ```
     CAPMESH_GOOGLE_ALLOWED_EMAILS=admin@example.com,newuser@gmail.com
     ```
   - Restart the capmesh service:
     ```bash
     sudo systemctl restart capmesh
     ```

3. **Grant Capmesh Role (if applicable)**
   - In capmesh, assign the appropriate role to the new user
   - This may be automatic or may require manual assignment depending on capmesh configuration

### Remove a User

1. **Remove from Google Cloud Console Test Users**
   - Navigate to **APIs & Services** → **OAuth consent screen**
   - Scroll to **Test users**
   - Click the trash icon next to the user's email
   - Confirm removal

2. **Update CAPMESH_GOOGLE_ALLOWED_EMAILS Environment Variable**
   - SSH to the capmesh host
   - Update `/etc/capmesh/google-secrets.env`:
     ```
     CAPMESH_GOOGLE_ALLOWED_EMAILS=admin@example.com
     ```
     (Remove the user's email from the comma-separated list)
   - Restart the capmesh service:
     ```bash
     sudo systemctl restart capmesh
     ```

3. **Revoke Capmesh Role (if applicable)**
   - In capmesh, remove the user's role or deactivate their account
   - This prevents the user from accessing capmesh even if they can sign in

## Troubleshooting

### Error: `redirect_uri_mismatch`

**Cause:** The redirect URI in the authorization request does not match the one registered in Google Cloud Console.

**Solution:**
- Verify that `CAPMESH_GOOGLE_REDIRECT_URI` environment variable is exactly:
  ```
  https://capmesh.example.local/api/v1/auth/google/callback
  ```
- Restart the capmesh service after making changes

### Error: `invalid_client`

**Cause:** The Client ID or Client Secret is incorrect or expired.

**Solution:**
- Verify the credentials in OpenBao:
  ```bash
  secret-manager get <path>/capmesh-google
  ```
- Confirm they match the Client ID and Secret from Google Cloud Console
- If they do not match, update them in OpenBao and restart capmesh

### Error: `access_denied` or User Not in Test Users

**Cause:** The user attempting to sign in is not in the OAuth consent screen's Test Users list.

**Solution:**
- Add the user to the Test Users list in Google Cloud Console (APIs & Services → OAuth consent screen)
- Update `CAPMESH_GOOGLE_ALLOWED_EMAILS` to include the user's email
- Restart capmesh
- The user can now sign in

### Error: `invalid_scope`

**Cause:** The OAuth scopes configured in capmesh do not match those approved in Google Cloud Console.

**Solution:**
- Verify in Google Cloud Console (APIs & Services → OAuth consent screen) that the following scopes are approved:
  ```
  openid
  email
  profile
  ```
- If missing, add them and restart capmesh

### User Can Sign In But Cannot Access Capmesh

**Cause:** The user has been authenticated but has not been granted a capmesh role.

**Solution:**
- In capmesh, assign the appropriate role to the user's email address
- The user can now access capmesh with their assigned permissions

## Rotating Credentials

To rotate the Google OAuth Client Secret (recommended annually or after a security incident):

1. **Generate a New Client Secret in Google Cloud Console**
   - Navigate to **APIs & Services** → **Credentials**
   - Click on the OAuth client (`Capmesh Google Sign-in`)
   - Under **Client secrets**, click **Generate a new secret**
   - Copy the new secret

2. **Update OpenBao**
   ```bash
   secret-manager put <path>/capmesh-google \
     client_id="<UNCHANGED_CLIENT_ID>" \
     web_client_secret="<NEW_SECRET>"
   ```

3. **Restart Capmesh**
   ```bash
   sudo systemctl restart capmesh
   ```

4. **Delete the Old Client Secret in Google Cloud Console** (optional but recommended)
   - Navigate to **APIs & Services** → **Credentials**
   - Click on the OAuth client
   - Under **Client secrets**, click the trash icon next to the old secret
   - Confirm deletion

## Further Reading

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Google Identity Platform](https://developers.google.com/identity)
- [OpenBao Key/Value Secrets Engine](https://www.openbao.org/docs/secrets/kv/kv-v2.html)
