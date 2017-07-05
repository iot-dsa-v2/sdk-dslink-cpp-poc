## Windows 10 Setup

1. install visual studio 2017
1. clone `https://github.com/Microsoft/vcpkg.git`
 into C:\vcpkg
1. run `.\bootstrap-vcpkg.bat` in vcpkg folder
1. install packages
```
.\vcpkg install boost:x64-windows
.\vcpkg install boost::x64-windows-static

.\vcpkg install openssl:x64-windows
.\vcpkg install openssl:x64-windows-static
```
1. run `.\vcpkg integrate install`
1. In visual studio, use `file-open-folder..` instead of creating project 


