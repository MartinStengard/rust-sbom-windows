extern crate winreg;
use std::path::Path;
use winreg::{
    enums::{RegType, HKEY_LOCAL_MACHINE, KEY_READ},
    types::FromRegValue,
    RegValue,
    RegKey,
};
use wmi::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Write};

fn main() {
    create_sbom_windows();
}

fn create_sbom_windows(){
    let metadata = get_metadata();
    let components_win32 = get_components_win32();
    let components_winreg32 = get_components_winreg32();
    let components_winreg64 = get_components_winreg64();
    let map_components: HashMap<String, String> = components_win32.into_iter().chain(components_winreg32).into_iter().chain(components_winreg64).collect();

    let components = map_components.values().map(|s| &**s).collect::<Vec<_>>().join(",");

    let mut result = String::from("{");
    result.push_str(&metadata);
    result.push_str("\"components\":[");
    result.push_str(&components);
    result.push_str("]");
    result.push_str("}");

    let mut output = File::create("output.txt").unwrap();
    let _res = write!(output, "{}", result);
}

fn get_metadata() -> String {
    let mut metadata = String::from(r#""metadata":{ 
        "manufacture":{ 
            "name":"<manufacture>" 
        }, 
        "component":{ 
            "name":"<op>", 
            "version":"<op_version>", 
            "type":"container" 
        }, 
        "properties":[ 
            {"host":"<host>"}, 
            {"model":"<systemfamily>"} 
        ]
    },"#);

    let query1 = "Select Manufacturer, Name, SystemFamily from win32_computerSystem".to_string();
    let computer_system = get_result(query1);

    for item in computer_system {
        for key in item.keys(){
            let value = item.get(key).unwrap();

            if key == "Manufacturer" {
                metadata = metadata.replace("<manufacture>", value);
            } else if key == "Name" {
                metadata = metadata.replace("<host>", value);
            } else if key == "SystemFamily" {
                metadata = metadata.replace("<systemfamily>", value);
            }
        }
    }

    let query2 = "Select Caption, Version from Win32_OperatingSystem".to_string();
    let operating_system = get_result(query2);

    for item in operating_system {
        for key in item.keys(){
            let value = item.get(key).unwrap();

            if key == "Caption" {
                metadata = metadata.replace("<op>", value);
            } else if key == "Version" {
                metadata = metadata.replace("<op_version>", value);
            }
        }
    }

    return metadata;
}

fn get_components_win32() -> HashMap<String, String> {
    let component = String::from(r#"{
        "name":"<name>",
        "type":"operating-system",
        "supplier":{
            "name":"<vendor>"
        },
        "version":"<version>"
    }"#);

    let mut programs: HashMap<String, String> = HashMap::new();

    let query = "Select Name, Vendor, Version from Win32_Product where Name is not null and Vendor is not null and Version is not null".to_string();
    let products = get_result(query);

    for product in products {
        let mut current = component.to_string();
        let mut insert_name = "".to_string();

        for key in product.keys(){
            let value = product.get(key).unwrap();

            if key == "Name" {
                current = current.replace("<name>", value);
                insert_name = value.to_string();
            } else if key == "Vendor" {
                current = current.replace("<vendor>", value);
            } else if key == "Version" {
                current = current.replace("<version>", value);
            }
        }

        if insert_name != ""{
            programs.insert(insert_name, current);
        }
    }
    
    return programs;
}

fn get_components_winreg32() -> HashMap<String, String> {
    let component = String::from(r#"{
        "name":"<name>",
        "type":"operating-system",
        "supplier":{
            "name":"<vendor>"
        },
        "version":"<version>"
    }"#);

    let mut programs: HashMap<String, String> = HashMap::new();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let curr_uninstall = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_READ).unwrap();
    
    for app_key in curr_uninstall.enum_keys(){
        let cur_app_key = app_key.unwrap().to_owned();
        let mut insert_name = "UNSET".to_string();

        let cur_app_path = Path::new("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall").join(cur_app_key);
        let cur_app = hklm.open_subkey(cur_app_path).unwrap();
        
        let mut cur_component = component.to_string();
        let mut component_found = false;

        for (name, value) in cur_app.enum_values().map(|x| x.unwrap()){
            if name == "DisplayName" {
                cur_component = cur_component.replace("<name>", &display_reg_value(&value));
                insert_name = display_reg_value(&value);
                component_found = true;
            } else if name == "DisplayVersion" {
                cur_component = cur_component.replace("<version>", &display_reg_value(&value));
            } else if name == "Publisher" {
                cur_component = cur_component.replace("<vendor>", &display_reg_value(&value));
            } else if name == "InstallSource" {
                //cur_component = cur_component.replace("<name>", &display_reg_value(&value));
            }
        }
        
        if component_found {
            programs.insert(insert_name, cur_component);
        }
    }

    return programs;
}

fn get_components_winreg64() -> HashMap<String, String> {
    let component = String::from(r#"{
        "name":"<name>",
        "type":"operating-system",
        "supplier":{
            "name":"<vendor>"
        },
        "version":"<version>"
    }"#);

    let mut programs: HashMap<String, String> = HashMap::new();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let curr_uninstall = hklm.open_subkey_with_flags("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_READ).unwrap();

    for app_key in curr_uninstall.enum_keys(){
        let cur_app_key = app_key.unwrap().to_owned();
        let mut insert_name = "UNSET".to_string();

        let cur_app_path = Path::new("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall").join(cur_app_key);
        let cur_app = hklm.open_subkey(cur_app_path).unwrap();

        let mut cur_component = component.to_string();
        let mut component_found = false;

        for (name, value) in cur_app.enum_values().map(|x| x.unwrap()){
            if name == "DisplayName" {
                cur_component = cur_component.replace("<name>", &display_reg_value(&value));
                insert_name = display_reg_value(&value);
                component_found = true;
            } else if name == "DisplayVersion" {
                cur_component = cur_component.replace("<version>", &display_reg_value(&value));
            } else if name == "Publisher" {
                cur_component = cur_component.replace("<vendor>", &display_reg_value(&value));
            } else if name == "InstallSource" {
                //cur_component = cur_component.replace("<name>", &display_reg_value(&value));
            }
        }
        
        if component_found {
            programs.insert(insert_name, cur_component);
        }
    }

    return programs;
}

fn get_result(query:String) -> Vec<HashMap<String, String>>  {
    let wmi_con = WMIConnection::new(COMLibrary::new().unwrap().into()).unwrap();
    let results: Vec<HashMap<String, String>> = match wmi_con.raw_query(&query) {
        Err(e) => {
            println!("Couldn't run query {} because of {:?}", query, e);
            return Vec::new();
        }
        Ok(results) => results,
    };
    return results;
}

fn display_reg_value(rv: &RegValue) -> String {
    match rv.vtype {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ | RegType::REG_MULTI_SZ => {
            String::from_reg_value(rv).unwrap_or_default()
        }
        RegType::REG_DWORD => u32::from_reg_value(rv).unwrap_or_default().to_string(),
        RegType::REG_QWORD => u64::from_reg_value(rv).unwrap_or_default().to_string(),
        _ => panic!("can only process reg value of type string, u32 or u64"),
    }
}