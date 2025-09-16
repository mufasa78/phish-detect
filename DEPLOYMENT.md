# 🚀 Streamlit Cloud Deployment Guide

## Prerequisites

1. **GitHub Repository**: Your code must be pushed to a GitHub repository
2. **Streamlit Cloud Account**: Sign up at [share.streamlit.io](https://share.streamlit.io)
3. **Database**: Ensure your PostgreSQL database (Neon) is accessible from the internet

## Deployment Steps

### 1. Push to GitHub

Make sure your code is committed and pushed to GitHub:

```bash
git add .
git commit -m "Prepare for Streamlit Cloud deployment"
git push origin main
```

### 2. Deploy on Streamlit Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Click "New app"
3. Connect your GitHub account if not already connected
4. Select your repository: `your-username/phish-detect`
5. Set the main file path: `app.py`
6. Click "Deploy!"

### 3. Configure Secrets

After deployment, you need to add your database credentials:

1. Go to your app's dashboard on Streamlit Cloud
2. Click on "Settings" → "Secrets"
3. Add the following configuration:

```toml
[database]
PGDATABASE = "neondb"
PGHOST = "ep-shiny-fire-agjbp4cz.c-2.eu-central-1.aws.neon.tech"
PGPORT = "5432"
PGUSER = "neondb_owner"
PGPASSWORD = "npg_bcR7k5LPjDZI"
```

4. Click "Save"

### 4. Verify Deployment

1. Wait for the app to rebuild (this happens automatically after adding secrets)
2. Test the database connection by clicking "View Database Report"
3. Upload test files to ensure the phishing detection works

## Important Notes

### Security
- **Never commit secrets.toml to GitHub** - it's already in `.gitignore`
- Database credentials are only stored in Streamlit Cloud's secure secrets management
- Your `.env.local` file is also ignored by git for local development

### Database Configuration
The app automatically detects the environment:
- **Streamlit Cloud**: Uses `st.secrets.database.*`
- **Local Development**: Uses `.env.local` file

### Troubleshooting

**Database Connection Issues:**
1. Verify your Neon database allows connections from `0.0.0.0/0` (all IPs)
2. Check that SSL is enabled in your database settings
3. Ensure all secret keys match exactly (case-sensitive)

**App Won't Start:**
1. Check the logs in Streamlit Cloud dashboard
2. Verify all dependencies are in `requirements.txt`
3. Ensure `app.py` is in the root directory

**File Upload Issues:**
1. Streamlit Cloud has file size limits (200MB per file)
2. Large email files may need to be compressed

## App URL

Once deployed, your app will be available at:
`https://your-app-name.streamlit.app`

## Updating the App

To update your deployed app:
1. Make changes to your code locally
2. Commit and push to GitHub
3. Streamlit Cloud will automatically redeploy

## Local Testing with Streamlit Secrets

To test locally with the same configuration as production:
1. Keep your `.streamlit/secrets.toml` file (not committed to git)
2. Run: `streamlit run app.py`
3. The app will use secrets.toml instead of .env.local

## Support

- [Streamlit Cloud Documentation](https://docs.streamlit.io/streamlit-cloud)
- [Streamlit Community Forum](https://discuss.streamlit.io/)
