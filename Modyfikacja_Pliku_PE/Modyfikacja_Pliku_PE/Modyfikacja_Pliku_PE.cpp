// Modyfikacja_Pliku_PE.cpp : Defines the entry point for the console application.
//
//ranomizacja adresu wylaczona w opcjach linkera
#include "stdafx.h"
#include <iostream>
#include <Windows.h>
using namespace std;

DWORD rvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt); //konwersja adresu wirtualnego na offset

int main()
{
	HANDLE hPlik, hMap;
	DWORD viewSize;
	LPVOID fileBase;
	LPSTR nazwaDLL = "ucrtbased.dll"; //nazwa biblioteki, w ktorej znajduje sie funkcja
	LPSTR nazwaPodmienianejFun = "sin"; //nazwa funkcji, ktora chce zmienic
	LPSTR nazwaFunDoPodmiany = "cos";
	LPSTR nazwaOdczytFun;
	LPSTR odczytanaDLL;

	hPlik = CreateFile(L"Przyklad.exe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	viewSize = GetFileSize(hPlik, NULL);
	hMap = CreateFileMapping(hPlik, NULL, PAGE_READWRITE, 0, 0, NULL);
	fileBase = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, viewSize);


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew); //pe header
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNTHeader); //wskaznik na pierwszy section header

	//pobieram adres wirtualny tabeli importow i jej rozmiar
	DWORD importTableAddr = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importTableSize = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		
	//kazda struktura IMAGE_IMPORT_TABLE dotyczy jednej dllki
	DWORD offset = rvaToOffset(importTableAddr, pSecHeader, pNTHeader);
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)fileBase + offset);
	

	PSTR pHintName;
	PIMAGE_IMPORT_BY_NAME pImportByName;
	PIMAGE_THUNK_DATA pThunk;
	FARPROC fProc;
	//while() przejscia po kolejnych dllkach
	while (pImportDescriptor->Name != NULL){ //przechodz, poki nie znajdziesz pustego IMAGE_IMPORT_DESCRIPTOR
		
		odczytanaDLL = (PSTR)((DWORD_PTR)fileBase + rvaToOffset(pImportDescriptor->Name, pSecHeader, pNTHeader));
		pThunk = (PIMAGE_THUNK_DATA)((DWORD)fileBase + pImportDescriptor->FirstThunk);

		if (lstrcmpiA(odczytanaDLL, nazwaDLL) == 0){

			pHintName = (PSTR)fileBase;

			if (pImportDescriptor->OriginalFirstThunk != 0)
				pHintName += rvaToOffset(pImportDescriptor->OriginalFirstThunk, pSecHeader, pNTHeader);
			else
				pHintName += rvaToOffset(pImportDescriptor->FirstThunk, pSecHeader, pNTHeader);
			
			
			PIMAGE_THUNK_DATA pImageThunkData = (PIMAGE_THUNK_DATA)pHintName;
			pImportByName = (PIMAGE_IMPORT_BY_NAME)pImageThunkData->u1.AddressOfData;

			DWORD  funcAddr, sinAddr, cosAddr;
			int flag = 0;
			//odczytywanie kolejnych funkcji
			while (pImageThunkData->u1.AddressOfData != 0){
				
				funcAddr = pImageThunkData->u1.AddressOfData; 
				nazwaOdczytFun = (PSTR)((DWORD_PTR)fileBase + rvaToOffset(funcAddr, pSecHeader, pNTHeader) + 2);
				
				if (lstrcmpiA(nazwaOdczytFun, nazwaPodmienianejFun) == 0){  //sin
					sinAddr = (DWORD)nazwaOdczytFun;

					++flag;
				}
				else if (lstrcmpiA(nazwaOdczytFun, nazwaFunDoPodmiany) == 0){ //cos
					cosAddr = (DWORD)nazwaOdczytFun;
					++flag;
				}
				
				if (flag == 2){ //znam adresy obu funkcji
					memcpy((void*)sinAddr, (void*)cosAddr, 4); //kopiuje adres cosinusa do sinusa
				}
				
				pThunk++;
				pImageThunkData++;

			}
			if(flag == 2)
				cout << "OK" << endl;
		}

		pImportDescriptor++; //skocz do kolejnego IMAGE_IMPORT_DESCRIPTOR

	}

	FlushViewOfFile(fileBase, viewSize);
	UnmapViewOfFile(fileBase);
	CloseHandle(hMap);
	CloseHandle(hPlik);

	system("pause");
	return 0;
}

DWORD rvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSecHeader;

	if (rva == 0)
		return rva;

	pSecHeader = psh;

	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++){
		if (rva >= pSecHeader->VirtualAddress && rva < pSecHeader->VirtualAddress + pSecHeader->Misc.VirtualSize)
			break;

		pSecHeader++; //kolejny IMAGE_SECTION_HEADER
	}

	return (rva - pSecHeader->VirtualAddress + pSecHeader->PointerToRawData);
}

