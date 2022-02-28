# SBOM for Windows ("Software Bills of Materials")
This program is created and run using Visual Code.

## Targets on Windows
This project generates a SBOM file for a Windows machine. It extract installed programs from:
- WMI query "Win32_Product"
- Key registry "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
- Key registry "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

Please send me a note on improvements and if you have use of this code.

## Format example
```
{
    "bomFormat":"CycloneDX",
    "specVersion":"1.4",
    "serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version":1,
    "metadata":{
        {
            "manufacture":{ 
            "name":"MyManufacture" 
        }, 
        "component":{ 
            "name":"Microsoft Windows 11 Pro", 
            "version":"10.0.22000", 
            "type":"container" 
        }, 
        "properties":[ 
            {"host":"MyComputerName"}, 
            {"model":"MyModel"} 
        ]
        }
    },
    "components":[
        {
            "name":"Microsoft ODBC Driver 17 for SQL Server",
            "type":"operating-system",
            "supplier":{
                "name":"Microsoft Corporation"
            },
            "version":"17.7.2.1"
        },
        {
            "name":"Python 3.9.5 Utility Scripts (64-bit)",
            "type":"operating-system",
            "supplier":{
                "name":"Python Software Foundation"
            },
            "version":"3.9.5150.0"
        },
        {
            "name":"Windows SDK for Windows Store Apps Tools",
            "type":"operating-system",
            "supplier":{
                "name":"Microsoft Corporation"
            },
            "version":"10.1.19041.685"
        }
    ]
}
```
