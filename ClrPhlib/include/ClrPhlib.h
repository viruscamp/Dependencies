// ClrPhlib.h

#pragma once

#include <UnmanagedPh.h>
#using <System.dll>

using namespace System;
using namespace Collections::Generic;

namespace Dependencies {

    namespace ClrPh {

		#pragma region ENUMS
		public enum class CLRPH_ARCH
		{
			x86,
			x64,
			WOW64
		};

		public enum class CLRPH_DEMANGLER
		{
			None,
			Demumble,
			LLVMItanium,
			LLVMMicrosoft,
			Microsoft,
			Default			// Synthetic demangler using all the previous ones
		};
		#pragma endregion ENUMS

		#pragma region TYPES
        public ref class ApiSetTarget : List<String^> {};

        public ref class ApiSetSchema abstract
        {
        public:
            virtual List<KeyValuePair<String^, ApiSetTarget^>>^ GetAll() = 0;
            virtual ApiSetTarget^ Lookup(String^ name) = 0;
        };
		#pragma endregion TYPES

        public ref class Phlib {
        public:

			// Return the arch is which ClrPhLib runs.
			static CLRPH_ARCH GetClrPhArch();

            // Imitialize Process Hacker's phlib internal data
            // Must be called before any other API (kinda like OleInitialize).
            static bool InitializePhLib();

            // Return the list of knwown dll for this system
            static List<String^>^ GetKnownDlls(_In_ bool Wow64Dlls);

            static List<String^>^ KnownDll64List;
            static List<String^>^ KnownDll32List;

            
            // Return the Api Set schema:
            // NB: Api set resolution rely on hash buckets who 
            // can contains more entries than this schema.
            static ApiSetSchema^ GetApiSetSchema();
        };

        public ref struct PeImport {
            UInt16 Hint;
            UInt16 Ordinal;
            String ^ Name;
            String ^ ModuleName;
            Boolean ImportByOrdinal;
            Boolean DelayImport;

            PeImport(const PPH_MAPPED_IMAGE_IMPORT_DLL importDll, size_t Index);
            PeImport(const PeImport ^ other);
            ~PeImport();

        };

        public ref struct PeImportDll {
        public:
            Int64 Flags;
            String ^Name;
            Int64 NumberOfEntries;
            List<PeImport^>^ ImportList;

            // constructors
            PeImportDll(const PPH_MAPPED_IMAGE_IMPORTS &PvMappedImports, size_t ImportDllIndex);
            PeImportDll(const PeImportDll ^ other);

            // destructors
            ~PeImportDll();

            // getters
            bool IsDelayLoad();

        protected:
            !PeImportDll();

        private:
            PPH_MAPPED_IMAGE_IMPORT_DLL ImportDll;
        };

        public ref struct PeExport {
            UInt16 Ordinal;
            String ^  Name; // may be NULL.
            Boolean ExportByOrdinal;
            Int64   VirtualAddress;
            String ^  ForwardedName;

			PeExport();
            PeExport(const PeExport ^ other);
            ~PeExport();

			static PeExport^ FromMapimg(const UnmanagedPE& refPe, size_t Index);

        };

        public ref struct PeProperties {
            Int16 Machine;
            DateTime ^ Time;
            Int16 Magic;

			Int64 ImageBase;
            Int32  SizeOfImage;
			Int64 EntryPoint;


            Int32 Checksum;
            Boolean CorrectChecksum;

            Int16 Subsystem;
            Tuple<Int16, Int16> ^SubsystemVersion;

            Int16 Characteristics;
            Int16 DllCharacteristics;

            UInt64 FileSize;
        };


        // C# visible class representing a parsed PE file
        public ref class PE
        {
        public:
            PE(_In_ String^ Filepath);
            ~PE();

            // Mapped the PE in memory and init infos
            bool Load();

            // Unmapped the PE from memory
            void Unload();

            // Check if the PE is 32-bit
            bool IsWow64Dll();

            // Check if the PE is 32-bit
            bool IsArm32Dll();

            // return the processorArchiture of PE
            String^ GetProcessor();

            // Return the ApiSetSchema
            ApiSetSchema^ GetApiSetSchema();

            // Return the list of functions exported by the PE
            List<PeExport ^>^ GetExports();

            // Return the list of functions imported by the PE, bundled by Dll name
            List<PeImportDll ^>^ GetImports();

            // Retrieve the manifest embedded within the PE
            // Return an empty string if there is none.
            String^ GetManifest();

            // PE properties parsed from the NT header
            PeProperties ^Properties;

            // Check if the specified file has been successfully parsed as a PE file.
            Boolean LoadSuccessful;

            // Path to PE file.
            String^ Filepath;

        protected:
            // Deallocate the native object on the finalizer just in case no destructor is called  
            !PE();

            // Initalize PeProperties struct once the PE has been loaded into memory
            bool InitProperties();

        private:
            
            // C++ part interfacing with phlib
            UnmanagedPE * m_Impl;

            // local cache for imports and exports list
            Lazy<List<PeImportDll^>^>^ m_Imports;
            Lazy<List<PeExport^>^>^ m_Exports;

            List<PeExport^>^ GetExportsInternal();
            List<PeImportDll^>^ GetImportsInternal();
        };
        
    }

}