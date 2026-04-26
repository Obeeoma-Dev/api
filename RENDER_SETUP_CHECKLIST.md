# Render Deployment Checklist

Your Render URL: **https://api-2-cnkp.onrender.com**

## ✅ Configuration Checklist

### 1. **Environment Variables on Render Dashboard**

Go to your Render service → Environment tab and add these:

```
SECRET_KEY=<generate-a-random-secret-key>
DEBUG=False
DATABASE_URL=<automatically-set-by-render-postgres>
ALLOWED_HOSTS=api-2-cnkp.onrender.com,.onrender.com

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=obeeoma256@gmail.com
EMAIL_HOST_PASSWORD=<your-gmail-app-password>
DEFAULT_FROM_EMAIL=obeeoma256@gmail.com

# Gmail API (if using Gmail API instead of SMTP)
GOOGLE_CLIENT_ID=<your-client-id>
GOOGLE_CLIENT_SECRET=<your-client-secret>
REFRESH_TOKEN=<your-refresh-token>

# Groq AI
GROQ_API_KEY=<your-groq-api-key>

# Cloudinary
CLOUDINARY_CLOUD_NAME=<your-cloud-name>
CLOUDINARY_API_KEY=<your-api-key>
CLOUDINARY_API_SECRET=<your-api-secret>

# MFA Encryption
FERNET_KEY=<generate-fernet-key>

# Frontend URL
FRONTEND_URL=https://your-frontend-url.com

# OpenAI (if using)
OPENAI_API_KEY=<your-openai-key>
OPENAI_MODEL=gpt-3.5-turbo
```

---

### 2. **Build Command** (in Render Dashboard)

```bash
./build.sh
```

Or if that doesn't work:
```bash
pip install -r requirements.txt && python manage.py collectstatic --no-input && python manage.py migrate
```

---

### 3. **Start Command** (in Render Dashboard)

```bash
gunicorn api.wsgi:application
```

---

### 4. **Files to Commit**

Make sure these files are in your repository:

- ✅ `build.sh` (created)
- ✅ `requirements.txt` (should include `gunicorn`, `dj-database-url`, `psycopg2-binary`)
- ✅ `api/settings.py` (updated with Render URL)
- ✅ `render.yaml` (optional, for infrastructure as code)

---

### 5. **Requirements.txt Must Include**

```txt
gunicorn
dj-database-url
psycopg2-binary
whitenoise
```

Check if these are in your `requirements.txt`. If not, add them.

---

### 6. **Database Setup**

- ✅ Create a PostgreSQL database on Render
- ✅ Link it to your web service
- ✅ Render will automatically set `DATABASE_URL`

---

### 7. **Static Files**

Your settings already have:
```python
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
```

This is correct for Render ✅

---

### 8. **Test Your Deployment**

After deployment, test these URLs:

1. **API Root:**
   ```
   https://api-2-cnkp.onrender.com/
   ```

2. **API Schema:**
   ```
   https://api-2-cnkp.onrender.com/api/v1/api/schema/
   ```

3. **Swagger Docs:**
   ```
   https://api-2-cnkp.onrender.com/api/v1/swagger/
   ```

4. **Admin Panel:**
   ```
   https://api-2-cnkp.onrender.com/admin/
   ```

---

### 9. **Common Issues & Fixes**

#### Issue: "Application failed to respond"
**Fix:** Check logs in Render dashboard. Usually missing environment variables.

#### Issue: "DisallowedHost"
**Fix:** Add your Render URL to `ALLOWED_HOSTS` in settings.py (already done ✅)

#### Issue: "Static files not loading"
**Fix:** Run `python manage.py collectstatic` in build command (already in build.sh ✅)

#### Issue: "Database connection error"
**Fix:** Make sure PostgreSQL database is created and linked to your service

#### Issue: "ModuleNotFoundError"
**Fix:** Add missing package to `requirements.txt`

---

### 10. **Commit and Push Changes**

```bash
git add .
git commit -m "Configure for Render deployment"
git push origin main
```

Render will automatically redeploy when you push to main branch.

---

## 🚀 Quick Verification Commands

Run these in your Render shell (Dashboard → Shell tab):

```bash
# Check if migrations ran
python manage.py showmigrations

# Create superuser
python manage.py createsuperuser

# Check database connection
python manage.py dbshell

# Test collectstatic
python manage.py collectstatic --dry-run
```

---

## 📊 Monitor Your Deployment

1. **Logs:** Render Dashboard → Logs tab
2. **Metrics:** Render Dashboard → Metrics tab
3. **Shell Access:** Render Dashboard → Shell tab

---

## ✅ Final Checklist

- [ ] Environment variables set on Render
- [ ] Database created and linked
- [ ] `build.sh` is executable (`chmod +x build.sh`)
- [ ] `requirements.txt` includes all dependencies
- [ ] Settings updated with Render URL
- [ ] Changes committed and pushed to GitHub
- [ ] Deployment successful (check logs)
- [ ] API endpoints responding
- [ ] Swagger docs accessible
- [ ] Admin panel accessible

---

## 🆘 Need Help?

If something isn't working:
1. Check Render logs for errors
2. Verify all environment variables are set
3. Make sure database is connected
4. Test locally first with `DEBUG=False`

Your deployment should be live at: **https://api-2-cnkp.onrender.com**
