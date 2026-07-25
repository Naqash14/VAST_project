#!/bin/bash
# Safe deployment script for Railway/Production

echo "🚀 Safe Deployment - VAST Scanner"
echo "================================="

# 1. Backup before deployment
echo "📦 Creating backup before deployment..."
BACKUP_DIR="$HOME/vast_backups"
mkdir -p "$BACKUP_DIR"
BACKUP_NAME="vast_backup_$(date '+%Y%m%d_%H%M%S')"
cp -r "$PWD" "$BACKUP_DIR/$BACKUP_NAME"
echo "✅ Backup saved to: $BACKUP_DIR/$BACKUP_NAME"

# 2. Push to GitHub (both repos)
echo "📤 Pushing to GitHub..."
git add .
git commit -m "Pre-deployment backup: $(date '+%Y-%m-%d %H:%M:%S')"
git push origin main
git push backup main

# 3. Run tests (if available)
# echo "🧪 Running tests..."
# python -m pytest tests/

# 4. Show status
echo ""
echo "📊 Deployment Status:"
echo "   Origin: $(git remote get-url origin)"
echo "   Backup: $(git remote get-url backup)"
echo "   Branch: $(git branch --show-current)"
echo "   Commit: $(git rev-parse --short HEAD)"

echo ""
echo "✅ Safe deployment complete!"
