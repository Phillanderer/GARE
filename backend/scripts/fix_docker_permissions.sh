#!/bin/bash
# Fix Docker permissions by adding user to docker group

echo "======================================"
echo "Fixing Docker Permissions"
echo "======================================"
echo ""

# Add current user to docker group
echo "Adding user '$USER' to docker group..."
sudo usermod -aG docker $USER

echo ""
echo "✓ User added to docker group"
echo ""
echo "IMPORTANT: You must log out and log back in for changes to take effect!"
echo ""
echo "Quick fix for this session (run this command):"
echo "  newgrp docker"
echo ""
echo "After running 'newgrp docker', try the smoke test again:"
echo "  ./scripts/smoke_test.sh /bin/ls"
echo ""
