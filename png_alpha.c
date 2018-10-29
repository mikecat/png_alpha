#if defined(_WIN32) && !defined(FORCE_NOT_WIN)
#define WIN_MODE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef WIN_MODE
#include <windows.h>
#include <inttypes.h>
#endif
#include <png.h>
#include <zlib.h>

#define VERSION "development version"

/* 1: exists 0: doesn't exist -1: error */
int file_exists(const char* path) {
	struct stat st;
	if (stat(path, &st) == 0) {
		return 1;
	} else if (errno == ENOENT) {
		return 0;
	} else {
		return -1;
	}
}

char* get_output_file_name(const char* input_name, const char* output_name) {
	if (output_name != NULL) {
		char* ret = malloc(strlen(output_name) + 1);
		if (ret == NULL) return NULL;
		strcpy(ret, output_name);
		return ret;
	} else {
		const char* suffix = "-alpha";
		size_t ret_max = strlen(input_name) + strlen(suffix) + 32;
		char* ret = malloc(ret_max);
		char* input_name_copy = malloc(strlen(input_name) + 2);
		char* ext;
		int fexists;
		if (ret == NULL || input_name_copy == NULL) {
			free(ret);
			free(input_name_copy);
			return NULL;
		}
		strcpy(input_name_copy, input_name);
		ext = strrchr(input_name_copy, '.');
		if (ext == NULL) {
			ext = input_name_copy + strlen(input_name_copy);
		} else {
			memmove(ext + 1, ext, strlen(ext) + 1);
			*ext = '\0';
			ext++;
		}
		snprintf(ret, ret_max, "%s%s%s", input_name_copy, suffix, ext);
		fexists = file_exists(ret);
		if (fexists == 0) {
			free(input_name_copy);
			return ret;
		} else if (fexists < 0) {
			free(ret);
			free(input_name_copy);
			return NULL;
		} else {
			unsigned int no = 2;
			for (;;) {
				snprintf(ret, ret_max, "%s%s-%u%s", input_name_copy, suffix, no, ext);
				fexists = file_exists(ret);
				if (fexists == 0) {
					free(input_name_copy);
					return ret;
				} else if (fexists < 0 || no == UINT_MAX) {
					free(ret);
					free(input_name_copy);
					return NULL;
				} else {
					no++;
				}
			}
		}
	}
}

#ifdef WIN_MODE
struct unicode_functions {
	HMODULE kernel32;
	HMODULE shell32;
	HMODULE user32;

	LPWSTR WINAPI (*GetCommandLine)(void);
	LPWSTR* WINAPI (*CommandLineToArgv)(LPCWSTR, int*);
	DWORD WINAPI (*GetFileAttributes)(LPCWSTR);
	HANDLE WINAPI (*CreateFile)(LPCWSTR, DWORD, DWORD,
		LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	int WINAPI (*lstrlen)(LPCWSTR);
	LPWSTR WINAPI (*lstrcpy)(LPWSTR, LPCWSTR);
	LPWSTR WINAPI (*lstrcat)(LPWSTR, LPCWSTR);
	int WINAPI (*wsprintf)(LPWSTR, LPCWSTR, ...);
};

/* 1: success 0: failed */
int load_functions(struct unicode_functions* funcs) {
	if ((funcs->kernel32 = LoadLibraryA("kernel32.dll")) == NULL) {
		funcs->shell32 = funcs->user32 = NULL;
		return 0;
	}
	if ((funcs->shell32 = LoadLibraryA("shell32.dll")) == NULL) {
		FreeLibrary(funcs->kernel32);
		funcs->kernel32 = funcs->user32 = NULL;
		return 0;
	}
	if ((funcs->user32 = LoadLibraryA("user32.dll")) == NULL) {
		FreeLibrary(funcs->kernel32);
		FreeLibrary(funcs->shell32);
		funcs->kernel32 = funcs->shell32 = NULL;
		return 0;
	}
	if ((funcs->GetCommandLine = (void*)GetProcAddress(funcs->kernel32, "GetCommandLineW")) &&
	(funcs->CommandLineToArgv = (void*)GetProcAddress(funcs->shell32, "CommandLineToArgvW")) &&
	(funcs->GetFileAttributes = (void*)GetProcAddress(funcs->kernel32, "GetFileAttributesW")) &&
	(funcs->CreateFile = (void*)GetProcAddress(funcs->kernel32, "CreateFileW")) &&
	(funcs->lstrlen = (void*)GetProcAddress(funcs->kernel32, "lstrlenW")) &&
	(funcs->lstrcpy = (void*)GetProcAddress(funcs->kernel32, "lstrcpyW")) &&
	(funcs->lstrcat = (void*)GetProcAddress(funcs->kernel32, "lstrcatW")) &&
	(funcs->wsprintf = (void*)GetProcAddress(funcs->user32, "wsprintfW"))) {
		return 1;
	} else {
		FreeLibrary(funcs->kernel32);
		FreeLibrary(funcs->shell32);
		FreeLibrary(funcs->user32);
		funcs->kernel32 = funcs->shell32 = funcs->user32 = NULL;
		return 0;
	}
}

void unload_functions(struct unicode_functions* funcs) {
	if (funcs->kernel32 != NULL) FreeLibrary(funcs->kernel32);
	if (funcs->shell32 != NULL) FreeLibrary(funcs->shell32);
	if (funcs->user32 != NULL) FreeLibrary(funcs->user32);
	funcs->kernel32 = funcs->shell32 = funcs->user32 = NULL;
}

/* 1: exists 0: doesn't exist -1: error */
int file_exists_w(const struct unicode_functions* funcs, LPCWSTR path) {
	DWORD attr = funcs->GetFileAttributes(path);
	if (attr == (DWORD)(-1)) {
		DWORD err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) return 0;
		return -1;
	} else {
		return 1;
	}
}

LPWSTR get_output_file_name_w(const struct unicode_functions* funcs,
LPCWSTR input_name, LPCWSTR output_name) {
	if (output_name != NULL) {
		LPWSTR ret = malloc(sizeof(*output_name) * (funcs->lstrlen(output_name) + 1));
		if (ret == NULL) return NULL;
		funcs->lstrcpy(ret, output_name);
		return ret;
	} else {
		LPCWSTR suffix = L"-alpha";
		size_t ret_max = funcs->lstrlen(input_name) + funcs->lstrlen(suffix) + 32;
		LPWSTR ret = malloc(sizeof(*ret) * ret_max);
		LPWSTR input_name_copy = malloc(sizeof(*input_name) * (funcs->lstrlen(input_name) + 2));
		LPWSTR ext, ext_search;
		int fexists;
		if (ret == NULL || input_name_copy == NULL) {
			free(ret);
			free(input_name_copy);
			return NULL;
		}
		funcs->lstrcpy(input_name_copy, input_name);
		for (ext = NULL, ext_search = input_name_copy; *ext_search != L'\0'; ext_search++) {
			if (*ext_search == L'.') ext = ext_search;
		}
		if (ext == NULL) {
			ext = input_name_copy + funcs->lstrlen(input_name_copy);
		} else {
			memmove(ext + 1, ext, sizeof(*ext) * (funcs->lstrlen(ext) + 1));
			*ext = L'\0';
			ext++;
		}
		funcs->lstrcpy(ret, input_name_copy);
		funcs->lstrcat(ret, suffix);
		funcs->lstrcat(ret, ext);
		fexists = file_exists_w(funcs, ret);
		if (fexists == 0) {
			free(input_name_copy);
			return ret;
		} else if (fexists < 0) {
			free(ret);
			free(input_name_copy);
			return NULL;
		} else {
			unsigned int no = 2;
			LPWSTR ret_suffix;
			funcs->lstrcpy(ret, input_name_copy);
			funcs->lstrcat(ret, suffix);
			funcs->lstrcat(ret, L"-");
			ret_suffix = ret + funcs->lstrlen(ret);
			for (;;) {
				funcs->wsprintf(ret_suffix, L"%u", no);
				funcs->lstrcat(ret_suffix, ext);
				fexists = file_exists_w(funcs, ret);
				if (fexists == 0) {
					free(input_name_copy);
					return ret;
				} else if (fexists < 0 || no == UINT_MAX) {
					free(ret);
					free(input_name_copy);
					return NULL;
				} else {
					no++;
				}
			}
		}
	}
}
#endif

void read_file(png_structp png_ptr, png_bytep data, size_t length) {
#ifdef WIN_MODE
	HANDLE hFile = *(HANDLE*)png_get_io_ptr(png_ptr);
	size_t lengthLeft = length;
	while (lengthLeft > 0) {
		DWORD lengthToRead = UINT32_C(0xffffffff);
		DWORD lengthRead = 0;
		if (lengthLeft < lengthToRead) lengthToRead = lengthLeft;
		if (!ReadFile(hFile, data, lengthToRead, &lengthRead, NULL) ||
		lengthToRead != lengthRead) {
			png_error(png_ptr, "file read error");
		}
		lengthLeft -= lengthRead;
		data += lengthRead;
	}
#else
	FILE* fp = png_get_io_ptr(png_ptr);
	if (fp == NULL) {
		png_error(png_ptr, "fp to read is NULL");
	}
	if (fread(data, length, 1, fp) != 1) {
		png_error(png_ptr, "file read error");
	}
#endif
}

void write_file(png_structp png_ptr, png_bytep data, size_t length) {
#ifdef WIN_MODE
	HANDLE hFile = *(HANDLE*)png_get_io_ptr(png_ptr);
	size_t lengthLeft = length;
	while (lengthLeft > 0) {
		DWORD lengthToWrite = UINT32_C(0xffffffff);
		DWORD lengthWritten = 0;
		if (lengthLeft < lengthToWrite) lengthToWrite = lengthLeft;
		if (!WriteFile(hFile, data, lengthToWrite, &lengthWritten, NULL) ||
		lengthToWrite != lengthWritten) {
			png_error(png_ptr, "file write error");
		}
		lengthLeft -= lengthWritten;
		data += lengthWritten;
	}
#else
	FILE* fp = png_get_io_ptr(png_ptr);
	if (fp == NULL) {
		png_error(png_ptr, "fp to write is NULL");
	}
	if (fwrite(data, length, 1, fp) != 1) {
		png_error(png_ptr, "file write error");
	}
#endif
}

void flush_file(png_structp png_ptr) {
#ifdef WIN_MODE
	HANDLE hFile = *(HANDLE*)png_get_io_ptr(png_ptr);
	if (!FlushFileBuffers(hFile)) {
		png_error(png_ptr, "file flush error");
	}
#else
	FILE* fp = png_get_io_ptr(png_ptr);
	if (fp == NULL) {
		png_error(png_ptr, "fp to flush is NULL");
	}
	if (fflush(fp) != 0) {
		png_error(png_ptr, "file flush error");
	}
#endif
}

int main(int argc, char* argv[]) {
	static png_byte chunks_to_ignore[] = {
		99, 72, 82, 77, 0, /* cHRM */
		115, 82, 71, 66, 0, /* sRGB */
		105, 67, 67, 80, 0, /* iCCP */
		101, 88, 73, 102, 0, /* eXIf */
		104, 73, 83, 84, 0, /* hIST */
		116, 69, 88, 116, 0, /* tEXt */
		122, 84, 88, 116, 0, /* zTXt */
		105, 84, 88, 116, 0, /* iTXt */
		115, 80, 76, 84, 0, /* sPLT */
		111, 70, 70, 115, 0, /* oFFs */
		112, 72, 89, 115, 0, /* pHYs */
		115, 67, 65, 76, 0, /* sCAL */
	};
	char* output_name = NULL;
#ifdef WIN_MODE
	HANDLE hFileIn;
	HANDLE hFileOut;
	struct unicode_functions funcs;
	int unicode_mode;
	LPWSTR* argv_w = NULL;
	int argc_w = 0;
	LPWSTR output_name_w;
#else
	FILE* fpin;
	FILE* fpout;
#endif
	png_structp png_in = NULL;
	png_infop info_in = NULL, end_info_in = NULL;
	png_structp png_out = NULL;
	png_infop info_out = NULL;
	png_uint_32 y;
	png_bytep row;

	int out_bit_depth, out_color_type;

	png_uint_32 width = 0, height = 0;
	int bit_depth = 0, color_type = 0;
	int interlace_type = 0, compression_type = 0, filter_method = 0;
	size_t row_size;

	int have_PLTE;
	png_colorp palette = NULL;
	int num_palette = 0;

	int have_gAMA;
	png_fixed_point file_gamma = 0;

	int have_sBIT;
	png_color_8p sig_bit;

	int have_tRNS;

	int have_bKGD;
	png_color_16p background;

	int num_unknowns1, num_unknowns2;
	png_unknown_chunkp unknowns1 = NULL, unknowns2 = NULL;

	if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "  %s input_file [output_file]\n", argc > 0 ? argv[0] : "png_alpha");
		fprintf(stderr, "  %s -h | --help | -v | --version\n", argc > 0 ? argv[0] : "png_alpha");
		return 1;
	} else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
		fprintf(stderr, "png_alpha " VERSION "\n");
		fprintf(stderr, "\nlibraries used:\n");
		fprintf(stderr, "%s\n", png_get_copyright(NULL));
		fprintf(stderr, "zlib %s\n", zlibVersion());
		return 0;
	}

#ifdef WIN_MODE
	unicode_mode = load_functions(&funcs);
	if (unicode_mode) {
		argv_w = funcs.CommandLineToArgv(funcs.GetCommandLine(), &argc_w);
		if (argv_w == NULL) {
			fprintf(stderr, "command line read failed\n");
			unload_functions(&funcs);
			return 1;
		}
	}
#define UNLOAD_FUNCTIONS unload_functions(&funcs);
#else
#define UNLOAD_FUNCTIONS
#endif

#ifdef WIN_MODE
	if (unicode_mode) {
		output_name_w = get_output_file_name_w(&funcs, argv_w[1], argc_w >= 3 ? argv_w[2] : NULL);
		if (output_name_w == NULL) {
			fprintf(stderr, "failed to decide output file name\n");
			UNLOAD_FUNCTIONS
			return 1;
		}
	} else {
#endif
		output_name = get_output_file_name(argv[1], argc >= 3 ? argv[2] : NULL);
		if (output_name == NULL) {
			fprintf(stderr, "failed to decide output file name\n");
			UNLOAD_FUNCTIONS
			return 1;
		}
#ifdef WIN_MODE
	}
#endif

#ifdef WIN_MODE
#define CLOSE_FPIN CloseHandle(hFileIn)
	if (unicode_mode) {
		hFileIn = funcs.CreateFile(argv_w[1], GENERIC_READ, 0, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
	} else {
		hFileIn = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
	}
	if (hFileIn == INVALID_HANDLE_VALUE) {
#else
#define CLOSE_FPIN fclose(fpin)
	fpin = fopen(argv[1], "rb");
	if (fpin == NULL) {
#endif
		fprintf(stderr, "failed to open input file %s\n", argv[1]);
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}

	png_in = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (png_in == NULL) {
		fprintf(stderr, "failed to create png_struct for input\n");
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}
	info_in = png_create_info_struct(png_in);
	if (info_in == NULL) {
		fprintf(stderr, "failed to create png_info for input\n");
		png_destroy_read_struct(&png_in, NULL, NULL);
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}
	end_info_in = png_create_info_struct(png_in);
	if (end_info_in == NULL) {
		fprintf(stderr, "failed to create 2nd png_info for input\n");
		png_destroy_read_struct(&png_in, &info_in, NULL);
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}
	if (setjmp(png_jmpbuf(png_in))) {
		png_destroy_read_struct(&png_in, &info_in, &end_info_in);
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}

	png_out = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (png_out == NULL) {
		fprintf(stderr, "failed to create png_struct for output\n");
		png_destroy_read_struct(&png_in, &info_in, &end_info_in);
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}
	info_out = png_create_info_struct(png_out);
	if (info_out == NULL) {
		fprintf(stderr, "failed to create png_info for output\n");
		png_destroy_read_struct(&png_in, &info_in, &end_info_in);
		png_destroy_write_struct(&png_out, NULL);
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}
	if (setjmp(png_jmpbuf(png_out))) {
		png_destroy_read_struct(&png_in, &info_in, &end_info_in);
		png_destroy_write_struct(&png_out, &info_out);
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}

#ifdef WIN_MODE
	png_set_read_fn(png_in, &hFileIn, read_file);
#else
	png_set_read_fn(png_in, fpin, read_file);
#endif
	png_set_keep_unknown_chunks(png_in, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
	png_set_keep_unknown_chunks(png_in, PNG_HANDLE_CHUNK_ALWAYS,
		chunks_to_ignore, sizeof(chunks_to_ignore) / 5);
	png_read_info(png_in, info_in);
	png_get_IHDR(png_in, info_in, &width, &height, &bit_depth, &color_type,
		&interlace_type, &compression_type, &filter_method);
	have_PLTE = png_get_PLTE(png_in, info_in, &palette, &num_palette);
	have_gAMA = png_get_gAMA_fixed(png_in, info_in, &file_gamma);
	have_sBIT = png_get_sBIT(png_in, info_in, &sig_bit);
	have_tRNS = png_get_valid(png_in, info_in, PNG_INFO_tRNS);
	have_bKGD = png_get_bKGD(png_in, info_in, &background);
	num_unknowns1 = png_get_unknown_chunks(png_in, info_in, &unknowns1);

	out_bit_depth = bit_depth <= 8 ? 8 : 16;
	out_color_type = (color_type & PNG_COLOR_MASK_COLOR) ?
		PNG_COLOR_TYPE_RGB_ALPHA : PNG_COLOR_TYPE_GRAY_ALPHA;

	if (color_type == PNG_COLOR_TYPE_PALETTE || have_tRNS || bit_depth < 8) {
		png_set_expand(png_in);
	}
	if (have_tRNS || (color_type & PNG_COLOR_MASK_ALPHA)) {
		png_color_16 back_data;
		png_color_16p use_back;
		if (have_bKGD) {
			use_back = background;
		} else {
			back_data.index = 0;
			if (bit_depth == 16) {
				back_data.red = back_data.green = back_data.blue = back_data.gray = 0xffff;
			} else {
				back_data.red = back_data.green = back_data.blue = back_data.gray = 0xff;
			}
			use_back = &back_data;
		}
		png_set_background(png_in, use_back, PNG_BACKGROUND_GAMMA_FILE, 0, 1);
	}
	png_set_filler(png_in, 0xffff, PNG_FILLER_AFTER);
	png_read_update_info(png_in, info_in);
	row_size = png_get_rowbytes(png_in, info_in);
	row = malloc(row_size);
	if (row == NULL) png_error(png_in, "allocating row failed");

#ifdef WIN_MODE
#define CLOSE_FPOUT CloseHandle(hFileOut)
	if (unicode_mode) {
		hFileOut = funcs.CreateFile(output_name_w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);
	} else {
		hFileOut = CreateFileA(output_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);
	}
	if (hFileOut == INVALID_HANDLE_VALUE) {
#else
#define CLOSE_FPOUT fclose(fpout)
	fpout = fopen(output_name, "wb");
	if (fpout == NULL) {
#endif
		fprintf(stderr, "failed to open output file %s\n", output_name);
		png_destroy_read_struct(&png_in, &info_in, &end_info_in);
		png_destroy_write_struct(&png_out, &info_out);
		CLOSE_FPIN;
		free(output_name);
		UNLOAD_FUNCTIONS
		return 1;
	}
	free(output_name);

#ifdef WIN_MODE
	png_set_write_fn(png_out, &hFileOut, write_file, flush_file);
#else
	png_set_write_fn(png_out, fpout, write_file, flush_file);
#endif
	png_set_keep_unknown_chunks(png_out, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
	png_set_keep_unknown_chunks(png_out, PNG_HANDLE_CHUNK_ALWAYS,
		chunks_to_ignore, sizeof(chunks_to_ignore) / 5);
	png_set_IHDR(png_out, info_out, width, height, out_bit_depth, out_color_type,
		interlace_type, compression_type, filter_method);
	if (have_PLTE) png_set_PLTE(png_out, info_out, palette, num_palette);
	if (have_gAMA) png_set_gAMA_fixed(png_out, info_out, file_gamma);
	if (have_sBIT) {
		png_color_8 out_sig_bit = *sig_bit;
		out_sig_bit.alpha = out_bit_depth;
		png_set_sBIT(png_out, info_out, &out_sig_bit);
	}
	if (have_bKGD) png_set_bKGD(png_out, info_out, background);
	if (num_unknowns1 > 0) {
		png_byte* location_bak = malloc(sizeof(png_byte ) * num_unknowns1);
		int i;
		if (location_bak == NULL) {
			png_error(png_out, "failed to allocate for unknown chunk location data 1");
		}
		for (i = 0; i < num_unknowns1; i++) location_bak[i] = unknowns1[i].location;
		png_set_unknown_chunks(png_out, info_out, unknowns1, num_unknowns1);
		for (i = 0; i < num_unknowns1; i++) unknowns1[i].location = location_bak[i];
		free(location_bak);
	}
	png_write_info(png_out, info_out);

	for (y = 0; y < height; y++) {
		png_read_row(png_in, row, NULL);
		if (y + 1 == height) row[row_size - 1] = 0xfe;
		png_write_row(png_out, row);
	}

	png_read_end(png_in, end_info_in);
	num_unknowns2 = png_get_unknown_chunks(png_in, info_in, &unknowns2);

	if (num_unknowns2 > 0) {
		png_byte* location_bak = malloc(sizeof(png_byte ) * num_unknowns2);
		int i;
		if (location_bak == NULL) {
			png_error(png_out, "failed to allocate for unknown chunk location data 2");
		}
		for (i = 0; i < num_unknowns2; i++) location_bak[i] = unknowns2[i].location;
		png_set_unknown_chunks(png_out, info_out, unknowns2, num_unknowns2);
		for (i = 0; i < num_unknowns2; i++) unknowns2[i].location = location_bak[i];
		free(location_bak);
	}
	png_write_end(png_out, info_out);

	png_destroy_read_struct(&png_in, &info_in, &end_info_in);
	png_destroy_write_struct(&png_out, &info_out);
	CLOSE_FPIN;
	CLOSE_FPOUT;
	UNLOAD_FUNCTIONS
	return 0;
}
