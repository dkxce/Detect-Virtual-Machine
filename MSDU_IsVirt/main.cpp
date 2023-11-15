//
// C++ (Win32, Win64)
// msdu_isvirt
// v 0.1, 14.11.2023
// https://github.com/dkxce/Detect-Virtual-Machine/
// en,ru,1251,utf-8
//

#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_DCOM

#include <algorithm>
#include <string>
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <comutil.h>
#include <stdio.h>

#include <windows.h>
#include <tchar.h>
#include <stdbool.h>

using namespace std;

#pragma comment(lib, "wbemuuid.lib")

BSTR Concat(BSTR a, BSTR b)
{
    UINT lengthA = SysStringLen(a);
    UINT lengthB = SysStringLen(b);

    BSTR result = SysAllocStringLen(NULL, lengthA + lengthB);

    memcpy(result, a, lengthA * sizeof(OLECHAR));
    memcpy(result + lengthA, b, lengthB * sizeof(OLECHAR));

    result[lengthA + lengthB] = 0;
    return result;
}

std::string bstr_to_str(BSTR source)
{

    _bstr_t wrapped_bstr = _bstr_t(source);
    int length = wrapped_bstr.length();
    char* char_array = new char[length];
    strcpy_s(char_array, length + 1, wrapped_bstr);
    return char_array;
}

std::string str_toupper(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

int main(int argc, char** argv)
{
    bool isVirt = false; /* NON VIRTUAL */
    string detecton = "Not Found Any Virtual Info";

    HRESULT hres;

    // Step 01: --------------------------------------------------
    // Initialize COM. ------------------------------------------
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) { return 1; };

    // Step 02: --------------------------------------------------
    // Set general COM security levels --------------------------
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) { CoUninitialize(); return 2; };

    // Step 03: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) { CoUninitialize(); return 3; };

    // Step 04: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) { pLoc->Release(); CoUninitialize(); return 4; };

    // Step 05: --------------------------------------------------
    // Set security levels on the proxy -------------------------
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return 5; };

    // Step 06: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----    

    // Step 06.0 --------------------------------------------------
    if (!isVirt)
    {
        HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (handle != INVALID_HANDLE_VALUE) { 
            CloseHandle(handle); 
            isVirt = true; 
            detecton = "\\\\.\\VBoxMiniRdrDN";
        }
        
        HKEY hKey = 0; DWORD dwType = REG_SZ; char buf[255] = { 0 }; DWORD dwBufSize = sizeof(buf);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) { 
            isVirt = true; 
            detecton = "Registry SOFTWARE\\VMware, Inc.\\VMware Tools";
        }
    };

    // Step 06.1 --------------------------------------------------
    // Win32_ComputerSystem: Manufacturer and Model
    string manufacturer = "";
    string model = "";
    if(!isVirt)
    {
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_ComputerSystem"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (!FAILED(hres))
        {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator)
            {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) { break; }

                try
                {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
                    if (vtProp.bstrVal != NULL)
                        manufacturer = str_toupper(bstr_to_str(SysAllocString(vtProp.bstrVal)));
                    hr = pclsObj->Get(L"Model", 0, &vtProp, 0, 0);
                    if (vtProp.bstrVal != NULL)
                        model = str_toupper(bstr_to_str(SysAllocString(vtProp.bstrVal)));
                    VariantClear(&vtProp);

                    pclsObj->Release();
                }
                catch (...){};

                // Hyper-V
                if ((manufacturer.find("MICROSOFT") != std::string::npos) && (model.find("VIRTUAL") != std::string::npos)) {
                    isVirt = true;
                    detecton = "Win32_ComputerSystem Hyper-V";
                };
                // VMWare
                if (manufacturer.find("VMWARE") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_ComputerSystem VMWARE";
                };
                // VirtualBox
                if (model == "VIRTUALBOX")
                {
                    isVirt = true;
                    detecton = "Win32_ComputerSystem VIRTUALBOX";
                };
                // VirtualPC
                if (model == "VIRTUAL MACHINE")
                {
                    isVirt = true;
                    detecton = "Win32_ComputerSystem VIRTUAL MACHINE";
                };
                // WMWare
                if (model.rfind("VMWARE", 0) == 0)
                {
                    isVirt = true;
                    detecton = "Win32_ComputerSystem VMWARE";
                };
            };

            pEnumerator->Release();
        };
    };

    // Step 06.2 --------------------------------------------------
    // Win32_BaseBoard: Manufacturer
    string baseboard = "";
    if (!isVirt)
    {
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_BaseBoard"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (!FAILED(hres))
        {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator)
            {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) { break; }

                try
                {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
                    if (vtProp.bstrVal != NULL)
                        baseboard = str_toupper(bstr_to_str(SysAllocString(vtProp.bstrVal)));
                    VariantClear(&vtProp);
                }
                catch (...) {};

                pclsObj->Release();

                // Hyper-V
                if (baseboard == "MICROSOFT CORPORATION")
                {
                    isVirt = true;
                    detecton = "Win32_BaseBoard Hyper-V";
                };
            };

            pEnumerator->Release();
        };
    };

    // Step 06.3 --------------------------------------------------
    // Win32_BIOS: SerialNumber
    string bios_sn = "";
    if(!isVirt)
    {
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_BIOS"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (!FAILED(hres))
        {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator)
            {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) { break; }

                try
                {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
                    if (vtProp.bstrVal != NULL)
                        bios_sn = str_toupper(bstr_to_str(SysAllocString(vtProp.bstrVal)));
                    VariantClear(&vtProp);
                    pclsObj->Release();
                }
                catch (...) {};

                // VMWare
                if (bios_sn.find("VMWARE") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_BIOS VMWARE";
                };
            };

            pEnumerator->Release();
        };
    };

    // Step 06.4 --------------------------------------------------   
    // Win32_DiskDrive: Model
    if (!isVirt)
    {
        string disk_model = "";
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_DiskDrive"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (!FAILED(hres))
        {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator)
            {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) { break; }

                try
                {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    hr = pclsObj->Get(L"Model", 0, &vtProp, 0, 0);
                    if (vtProp.bstrVal != NULL)
                        disk_model = str_toupper(bstr_to_str(SysAllocString(vtProp.bstrVal)));
                    VariantClear(&vtProp);
                    pclsObj->Release();
                }
                catch (...) {};

                // Hyper-V
                if (disk_model.find("VIRTUAL") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_DiskDrive Hyper-V";
                };
                // VMWare
                if (disk_model.find("VMWARE") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_DiskDrive VMWare";
                };
                // QEmu
                if (disk_model.find("QEMU") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_DiskDrive QEmu";
                };
                // VBox
                if (disk_model.find("VBOX") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_DiskDrive VBox";
                };
            };

            pEnumerator->Release();
        };
    };

    // Step 06.5 --------------------------------------------------    
    // Win32_PnPEntity: Name
    if (!isVirt)
    {
        string pnp_device = "";
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_PnPEntity"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (!FAILED(hres))
        {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator)
            {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) { break; }

                try
                {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                    if (vtProp.bstrVal != NULL)
                        pnp_device = str_toupper(bstr_to_str(SysAllocString(vtProp.bstrVal)));
                    VariantClear(&vtProp);
                    pclsObj->Release();
                }
                catch (...) {};

                // VMWare
                if (pnp_device == "VMWARE POINTING DEVICE")
                {
                    isVirt = true;
                    detecton = "Win32_PnPEntity VMWare";
                };
                if (pnp_device == "VMWARE USB POINTING DEVICE")
                {
                    isVirt = true;
                    detecton = "Win32_PnPEntity VMWare";
                };
                if (pnp_device == "VMWARE VMCU BUS DEVICE")
                {
                    isVirt = true;
                    detecton = "Win32_PnPEntity VMWare";
                };
                if (pnp_device == "VMWARE VIRTUAL S SCSI DISK DEVICE")
                {
                    isVirt = true;
                    detecton = "Win32_PnPEntity VMWare";
                };
                if (pnp_device.find("VMWARE SATA") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_PnPEntity VMWare";
                };
                if (pnp_device.rfind("VMWARE SVGA") == 0)
                {
                    isVirt = true;
                    detecton = "Win32_PnPEntity VMWare";
                };
                // Virtual Box
                if (pnp_device.find("VBOX") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_PnPEntity Virtual Box";
                };
            };

            pEnumerator->Release();
        };
    };

    // Step 06.6 -------------------------------------------------- 
    // Win32_Service: Name    
    if (!isVirt)
    {
        string service = "";
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_Service"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        if (!FAILED(hres))
        {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator)
            {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) { break; }

                try
                {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                    if (vtProp.bstrVal != NULL)
                        service = str_toupper(bstr_to_str(SysAllocString(vtProp.bstrVal)));
                    VariantClear(&vtProp);
                    pclsObj->Release();
                }
                catch (...) {};

                // VMWare
                if (service == "WMTOOLS")
                {
                    isVirt = true;
                    detecton = "Win32_Service VMWare";
                };
                if (service == "TPVCGATEWAY")
                {
                    isVirt = true;
                    detecton = "Win32_Service VMWare";
                };
                if (service == "TPAUTOCONNSVC")
                {
                    isVirt = true;
                    detecton = "Win32_Service VMWare";
                };
                // Virtual PC
                if (service.find("VPCMAP") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_Service Virtual PC";
                };
                if (service.find("WMSRVC") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_Service Virtual PC";
                };
                if (service.find("VMUSRVC") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_Service Virtual PC";
                };
                // VBox
                if (service.find("VBOXSERVICE") != std::string::npos)
                {
                    isVirt = true;
                    detecton = "Win32_Service VBox";
                };
            };

            pEnumerator->Release();
        };
    };


    // Step 07: --------------------------------------------------
    // Print IsVirt
    if (isVirt) wcout << "9 YES, Machine is Virtual" << endl;
    else wcout << "0 NO, Machine is Phisical" << endl;
    if (isVirt) wcout << "Device is:    " << "Virtual" << endl;
    else wcout << "Device is:    " << "Phisical" << endl;
    wcout << "Detected on:  " << detecton.c_str() << endl;
    wcout << "Manufacturer: " << manufacturer.c_str() << endl;
    wcout << "Model:        " << model.c_str() << endl;
    wcout << "BaseBoard:    " << baseboard.c_str() << endl;
    wcout << "BIOS SN:      " << bios_sn.c_str() << endl;
	

    // Step 08: --------------------------------------------------
    // Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
	

    // Step 09: --------------------------------------------------
    // Exit Ok
    if (isVirt) return 9; // YES, Machine is Virtual
    else return 0; // NO, Machine is Phisical
}