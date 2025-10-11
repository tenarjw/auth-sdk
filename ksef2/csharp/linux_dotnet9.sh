wget https://dotnetcli.azureedge.net/dotnet/Sdk/9.0.100/dotnet-sdk-9.0.100-linux-x64.tar.gz
sudo mkdir -p /usr/share/dotnet
sudo tar zxf dotnet-sdk-9.0.100-linux-x64.tar.gz -C /usr/share/dotnet
echo 'export PATH=$PATH:/usr/share/dotnet' | sudo tee -a /etc/profile
source /etc/profile
dotnet --version