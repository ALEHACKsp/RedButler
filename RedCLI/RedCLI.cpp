#include <iostream>
#include <vector>

#include <locale>
#include <codecvt>
#include <string>

#include "RedLibrary.h"
#include "args.hxx"

Red::Butler driver;

bool OpenDriver(Red::Butler& driver) {
	try {
		driver.Open();
	}
	catch (Red::Exception& e) {
		std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
		return false;
	}

	return true;
}

void ProcessCommand(args::Subparser& parser) {
	args::Group arguments(parser, "arguments", args::Group::Validators::All);

		args::Group actions(arguments, "actions", args::Group::Validators::Xor);
			args::Flag protect(actions, "protect", "protect the process", { "protect" });
			args::Flag unprotect(actions, "unprotect", "unprotect the process", { "unprotect" });
			args::Flag exclude(actions, "exclude", "exclude the process", { "exclude" });
			args::Flag unexclude(actions, "unexclude", "unexclude the process", { "unexclude" });
			args::Flag clear(actions, "clear", "clear the process attributes", { "clear" });

		args::Positional<DWORD> pid(arguments, "pid", "the target process id", args::Options::Required);

	parser.Parse();

	if (!OpenDriver(driver))
		return;

	if (protect) {
		try {
			driver.ProtectProcess(args::get(pid));
			std::cout << "Success!" << std::endl;
		}
		
		catch (Red::Exception& e) {
			std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
		}
	} else if (unprotect) {
		try {
			driver.UnprotectProcess(args::get(pid));
			std::cout << "Success!" << std::endl;
		}

		catch (Red::Exception& e) {
			std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
		}
	} else if (exclude) {
		try {
			driver.ExcludeProcess(args::get(pid));
			std::cout << "Success!" << std::endl;
		}

		catch (Red::Exception& e) {
			std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
		}
	} else if (unexclude) {
		try {
			driver.UnexcludeProcess(args::get(pid));
			std::cout << "Success!" << std::endl;
		}

		catch (Red::Exception& e) {
			std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
		}
	} else if (clear) {
		try {
			driver.ClearProcessAttributes(args::get(pid));
			std::cout << "Success!" << std::endl;
		}

		catch (Red::Exception& e) {
			std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
		}
	}

	driver.Close();
}

void FilesystemCommand(args::Subparser& parser) {
	args::Group arguments(parser, "arguments", args::Group::Validators::All);

		args::Group actions(arguments, "actions", args::Group::Validators::Xor);
			args::Flag hide(actions, "hide", "hide the target object", { "hide" });
			args::Flag unhide(actions, "unhide", "unhide the target object", { "unhide" });

		args::Group objects(arguments, "objects", args::Group::Validators::Xor);
			args::Flag file(objects, "file", "the process is a file", { "file", 'F' });
			args::Flag directory(objects, "directory", "the object is a directory", { "directory", 'D' });

		args::Positional<std::string> object(arguments, "object", "the actual object", args::Options::Required);

	parser.Parse();

	if (!OpenDriver(driver))
		return;

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

	if (hide) {
		if (file) {
			try {
				std::cout << "Hiding file " << object.Get() << "..." << std::endl;
				ULONG uObjectId = driver.HideFile(converter.from_bytes(object.Get()));
				std::cout << "Success! Object ID: " << uObjectId << std::endl;
			}

			catch (Red::Exception& e) {
				std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
			}
		} else if (directory) {
			try {
				std::cout << "Hiding directory " << object.Get() << "..." << std::endl;
				ULONG uObjectId = driver.HideDirectory(converter.from_bytes(object.Get()));
				std::cout << "Success! Object ID: " << uObjectId << std::endl;
			}

			catch (Red::Exception& e) {
				std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
			}
		}
	} else if (unhide) {
		if (file) {
			try {
				std::cout << "Unhiding file " << object.Get() << "..." << std::endl;
				driver.UnhideFile(strtoul(object.Get().c_str(), NULL, 10));
				std::cout << "Success!" << std::endl;
			}

			catch (Red::Exception& e) {
				std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
			}
		} else if (directory) {
			try {
				std::cout << "Unhiding directory " << object.Get() << "..." << std::endl;
				driver.UnhideDirectory(strtoul(object.Get().c_str(), NULL, 10));
				std::cout << "Success!" << std::endl;
			}

			catch (Red::Exception& e) {
				std::wcerr << "Error " << e.Code() << ": " << e.What() << std::endl;
			}
		}
	}

	driver.Close();
}

int main(int argc, char** argv) {
	args::ArgumentParser parser("RedButler official CLI application");
	
	args::Group commands(parser, "commands", args::Group::Validators::Xor);
	args::Command process(commands, "process", "interact with processes", &ProcessCommand);
	args::Command filesystem(commands, "filesystem", "interact with the filesystem", &FilesystemCommand);

	args::HelpFlag help(parser, "help", "Display this help menu", { 'h', "help" });

	try {
		parser.ParseCLI(argc, argv);
	} 
	
	catch (args::Help& e) {
		std::cout << parser;
	} 
	
	catch (args::Error& e) {
		std::cerr << e.what() << std::endl << parser;
		return 1;
	}

	return 0;
}
