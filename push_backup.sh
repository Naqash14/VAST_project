#!/bin/bash
# Quick backup script - push to both repos

echo "📤 Pushing to GitHub repositories..."

# Push to origin (main repo)
git push origin main

# Push to backup repo
git push backup main

echo "✅ Backup complete!"
echo ""
echo "📊 Repository status:"
git remote -v
