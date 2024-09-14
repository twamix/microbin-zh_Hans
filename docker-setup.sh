#!/bin/bash

# Check if wget is installed; if not, try to use curl
if ! command -v wget &> /dev/null
then
    download_command="curl -O"
else
    download_command="wget"
fi

# Get installation directory from user
echo -e "\033[1m请输入安装目录 (默认: /usr/share/microbin-zh_Hans):\033[0m"
read install_dir
install_dir=${install_dir:-/usr/share/microbin-zh_Hans}

# Create directory and download files
mkdir -p $install_dir
cd $install_dir
$download_command https://raw.githubusercontent.com/kyleyh838/microbin-zh_Hans/master/.env
$download_command https://raw.githubusercontent.com/kyleyh838/microbin-zh_Hans/master/compose.yaml

# Get public path URL and port from user
echo -e "\033[1m请输入站点链接 (示例: https://microbin.myserver.net 或 http://localhost:8080):\033[0m"
read public_path

echo -e "\033[1m请输入服务监听端口 (默认: 8080):\033[0m"
read port
port=${port:-8080}

# Update environment variables in .env file
if [[ -n "${public_path}" ]]; then  
    sed -i "s|^#\s*export MICROBIN_PUBLIC_PATH=.*|export MICROBIN_PUBLIC_PATH=${public_path}|" .env
fi
sed -i "s|MICROBIN_PORT=.*|MICROBIN_PORT=${port}|" .env

# Start Microbin using Docker Compose
docker compose --env-file .env up --detach

if [[ -n "${public_path}" ]]; then  
    echo -e "\033[1;32m安装完成，使用${public_path}访问服务!\033[0m"  
else  
    echo -e "\033[1;32m安装完成，使用http://IP:${port}访问服务!\033[0m"  
fi

