/*
 * MIT License
 * 
 * Copyright (c) 2020 Quentin Deslandes
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <getopt.h>
#include <libgen.h>

#define CWD_LEN 128

#define B_TO_MIB(size) (((size) / 1024.0) / 1024.0)
#define ptrdiff(from, to) ((unsigned long)((to) - (from)))

/*
 * struct tf_path - Filesystem path and its length. Used to save from computing
 * 	the path's length each time needed.
 * @str Path.
 * @len Path's length.
 */
struct tf_path {
	const char *str;
	size_t len;
};

/*
 * struct tf_path_list - List of paths.
 * @paths Pointer to the paths list.
 * @count Number of paths in the list.
 */
struct tf_path_list {
	struct tf_path *paths;
	size_t count;
};

/*
 * struct tf_options - Application options.
 * @cwd Current working directory, used to generate absolute paths.
 * @allow Allowed paths.
 * @exclude Excluded paths.
 */
struct tf_options {
        char cwd[CWD_LEN];
	struct tf_path_list allow;
	struct tf_path_list exclude;	
};

static char buffer[65536];
static bool verbose = false;

/*
 * tf_add_to_list() - Add an path to a path list.
 * @list List to add path to.
 * @path Path to add to the list.
 * 
 * Add the given path to the list, as lists doesn't have more space than the
 * required to store all the paths, we need to reallocate it to add room for
 * one more path.
 * 
 * Return 0 on success or negative error code on failure. On error, the
 * original list is unchanged.
 */
static int tf_add_to_list(struct tf_path_list *list, char *path)
{
	struct tf_path *l;

	l = realloc(list->paths, (list->count + 1) * sizeof(*list->paths));
        if (!l) {
                fprintf(stderr, "Can't reallocate list\n");
                return -ENOMEM;
        }

        l[list->count].str = path;
	l[list->count].len = strlen(path);
        ++list->count;

        list->paths = l;

        return 0;
}

/*
 * tf_skip_line() - From the tag file data and the current index in it, return
 * 	the index of the next line.
 * @tf Tag file data.
 * @idx Current index in buffer.
 * 
 * We assume that each line ends with a '\n' character, including the last one.
 * Hence, we can safely use strchr() to find the next '\n' character, which
 * will leads to AVX/SSE optimized functions on certain platforms.
 * 
 * Returns index of newline in tag file buffer.
 */
static inline size_t tf_skip_line(const char *tf, size_t idx)
{
        return ptrdiff(tf, strchr(&tf[idx], '\n')) + 1;
}

/*
 * tf_allowed() - Check if the given filepath is specifically allowed in
 *      given options.
 * @filepath Filepath to check.
 * @allowed Allowed paths.
 * 
 * We compare @filepath and allowed path up to the length of the allowed path
 * tested, as we only need to check the beginning of @filepath.
 * 
 * Returns true if the file is allowed, false otherwise.
 */
static bool tf_allowed(const char *filepath, struct tf_path_list *allowed)
{
        size_t len;
        const char *path;

        for (size_t i = 0; i < allowed->count; ++i) {
                path = allowed->paths[i].str;
                len = allowed->paths[i].len;

                if (strncmp(filepath, path, len) == 0)
                        return true;
        }

        return false;
}

/*
 * tf_excluded() - Check if the given filepath is excluded in given options.
 * @filepath Filepath to check.
 * @excluded Excluded paths.
 * 
 * We compare @filepath and excluded path up to the length of the excluded path
 * tested, as we only need to check the beginning of @filepath.
 * 
 * Returns true if the file is excluded, false otherwise.
 */
static bool tf_excluded(const char *filepath, struct tf_path_list *excluded)
{
        size_t len;
        const char *path;

        for (size_t i = 0; i < excluded->count; ++i) {
                path = excluded->paths[i].str;
                len = excluded->paths[i].len;

                if (strncmp(filepath, path, len) == 0)
			return true;
        }

        return false;
}

/*
 * parse_tagfile() - Parse given tag file data with options.
 * @tf Tag file data.
 * @len Length of the tag file data buffer.
 * @opts Options to allow or exclude paths.
 * 
 * Use stdlib's string manipulation functions as we want to take advantage of
 * SSE and AVX optimized functions. Also, used the unlocked version of
 * fwrite() as it's find in this context.
 */
static void parse_tagfile(const char *tf, size_t len, struct tf_options *opts)
{
        size_t idx = 0;
        const char *file;
	const char *last;

        /*
         * At the beginning of the tag file, there are a few lines related
         * to the ctag binary starting with '!', we skip them.
         */
        while (tf[idx] == '!')
                idx = tf_skip_line(tf, idx);

        while (idx != len) {
                file = strchr(&tf[idx], '/');

		last = file;
		while ((last = strchr(last, ';')) && *(last+1) != '"')
			++last;

                if (!tf_excluded(file, &opts->exclude) ||
		    tf_allowed(file, &opts->allow)) {
                        fwrite_unlocked(&tf[idx], 1, ptrdiff(&tf[idx], last),
					stdout);
                        fwrite_unlocked("\n", 1, 1, stdout);
                }

                idx = tf_skip_line(tf, idx + ptrdiff(&tf[idx], last));
        }
}

/*
 * parse_tagfiles() - Parse a list of tag files and print each tag to stdout.
 * @tagfile Path to the tag file.
 * @opts Reading options.
 * 
 * Tag file are mmap'd to the process addresses space to read faster.
 * 
 * Returns 0 on success or negative error code on failure.
 */
static int parse_tagfiles(const char *tagfile, struct tf_options *opts)
{
        int fd;
        int ret;
        struct stat stats;
        const char *tf_data;

        fd = open(tagfile, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "Can't open %s: %s\n", tagfile,
                        strerror(errno));
                ret = errno;
                goto end;
        }

        ret = fstat(fd, &stats);
        if (ret) {
                fprintf(stderr, "Can't get size of %s: %s\n", tagfile,
                        strerror(errno));
                ret = errno;
                goto end_close;
        }

        if (verbose)
                printf("Tag file is %7.2lfMB\n", B_TO_MIB(stats.st_size));

        tf_data = mmap(0, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (tf_data == MAP_FAILED) {
                fprintf(stderr, "Can't mmap() %s: %s\n", tagfile,
                        strerror(errno));
                ret = errno;
                goto end_unmap;
        }

        if (verbose)
                printf("TF mapped to 0x%08lx\n", (unsigned long)tf_data);

        parse_tagfile(tf_data, stats.st_size, opts);

end_unmap:
        munmap((void *)tf_data, stats.st_size);
end_close:
        close(fd);
end:
        return ret;
}

/*
 * opts_get_sanitized_path() - Sanitize given path by transforming it to an
 *      absolute path, convert any filepath to its containing directory and
 *      remove potential trailing '/'.
 * @base Absolute path of the base directory, used to generate absolute path
 *      if @path is relative, **without any trailing '/'**.
 * @path Path to sanitize.
 * 
 * Allocate a new string to contain the sanitized path, the string must be
 * freed by the caller.
 * 
 * Return pointer to sanitized path, or NULL on error.
 */
static char *opts_get_sanitized_path(const char *base, const char *path)
{
        int ret;
        char *spath;
        struct stat f_stats;
        size_t len = (strlen(base) + 1) * !(path[0] == '/') + strlen(path) + 1;

        // Convert to absolute path if needed
        spath = malloc(len);
        if (!spath) {
                fprintf(stderr, "Can't allocate memory for sanitized path\n");
                return NULL;
        }

        if (path[0] == '/') {
		// Given path must be a subdirectory of CWD
		if (strncmp(path, base, strlen(base)))
			goto err_free;

                strcpy(spath, path);
	} else {
                sprintf(spath, "%s/%s", base, path);
	}

        // If path is a file, use containing directory
        ret = stat(spath, &f_stats);
        if (ret) {
                fprintf(stderr, "Can't read %s: %s\n", spath, strerror(errno));
                goto err_free;
        }

        if (!S_ISDIR(f_stats.st_mode))
                spath = dirname(spath);

        // Removing potential trailing slash
        len = strlen(spath);
        if (spath[len - 1] == '/')
                spath[len - 1] = '\0';

        return spath;

err_free:
        free(spath);
        return NULL;
}

/*
 * opts_sanitize() - Sanitize program's options by convertin every path given
 *      to an absolute path to a directory.
 * @opts Options to sanitize.
 * 
 * All path representing directories in the application are sanitized. If any
 * allow or exclude path can't be sanitized we pass, as we just won't use it
 * to filter.
 * 
 * Any allowed or excluded full path that does not starts with base path is
 * discarded.
 */
static void opts_sanitize(struct tf_options *opts)
{
	size_t i;
        char *spath;
	size_t idx = 0;

        for (i = 0, idx = 0; i < opts->allow.count; ++i) {
                spath = opts_get_sanitized_path(opts->cwd,
						opts->allow.paths[i].str);

                if (spath) {
			opts->allow.paths[idx].str = spath;
			opts->allow.paths[idx].len = strlen(spath);
			++idx;
                }
        }

	opts->allow.count = idx;

        for (i = 0, idx = 0; i < opts->exclude.count; ++i) {
                spath = opts_get_sanitized_path(opts->cwd,
						opts->exclude.paths[i].str);

                if (spath) {
                        opts->exclude.paths[idx].str = spath;
			opts->exclude.paths[idx].len = strlen(spath);
			++idx;
                }
        }

	opts->exclude.count = idx;
}

/*
 * opts_free() - Free options structure. We won't free allow and exclude lists
 *      as they have not been allocated by opts_sanitize().
 * @opts Options to free.
 */
static void opts_free(struct tf_options *opts)
{
        for (size_t i = 0; i < opts->allow.count; ++i)
                free((void *)opts->allow.paths[i].str);

        for (size_t i = 0; i < opts->exclude.count; ++i)
                free((void *)opts->exclude.paths[i].str);
}

static void usage(void)
{
        fprintf(stderr, "\
Usage: ctagsparse [OPTION]... TAG_FILE...\n\
Parse and filter CTag tags file(s), output result as \"symbol<tab>file<tab>line\"\n\
\n\
Relative path send as argument are converted to absolute path based on\n\
current working directory.\n\
\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -e, --exclude=PATH PATH to exclude. If PATH is a file, it will be converted\n\
                     to the file's parent directory and excluded. Any source\n\
                     file matched which path starts with excluded PATH (or\n\
                     base path + excluded PATH if relative) won't be displayed\n\
                     in results.\n\
  -a, --allow=PATH   PATH to allow. If PATH is a file, it will be converted\n\
                     to the file's parent directory. If a given path is \n\
                     excluded by an --exclude directory, if it's allowed \n\
                     by --allow it won't by filtered out.\n\
  -h, --help         Display this help message.\n\
\n\
");
}

int main(int argc, char *argv[])
{
        int opt;
        char *cwd;
        int ret = EXIT_SUCCESS;
        struct tf_options options = { };
        struct option longopts[] = {
                { "allow", required_argument, NULL, 'a' },
                { "exclude", required_argument, NULL, 'e' },
                { "help", no_argument, NULL, 'h' },
                { 0 },
        };

	// Use custom buffer for stdout operations
        setvbuf(stdout, buffer, _IOFBF, 65536);

        // getopt() should not print any error message
        opterr = 0;

        cwd = getcwd(options.cwd, CWD_LEN);
        if (!cwd) {
                fprintf(stderr, "Can't get current working directory: %s\n",
                        strerror(errno));
                ret = EXIT_FAILURE;
                goto end;
        }

        while ((opt = getopt_long(argc, argv, ":hva:c:e:", longopts, NULL)) != -1) {
                switch (opt) {
                case '?':
                        fprintf(stderr, "Unknown option -%c\n", optopt);
                        ret = EXIT_FAILURE;
                        goto end_free;
                case ':':
                        fprintf(stderr, "Missing argument for -%c\n", optopt);
                        ret = EXIT_FAILURE;
                        goto end_free;
                case 'h':
                        usage();
                        goto end_free;
                case 'v':
                        verbose = true;
                        break;
                case 'a':
                        tf_add_to_list(&options.allow, optarg);
                        break;
                case 'e':
                        tf_add_to_list(&options.exclude, optarg);
                        break;
                default:
                        fprintf(stderr, "Unknown getopt_long() return value: %d\n",
                                opt);
                        ret = EXIT_FAILURE;
                        goto end_free;
                }
        }

        opts_sanitize(&options);

        if (verbose) {
		printf("=== ctagsparse ===\n");
                printf("Options:\n");
                printf("\tCWD: %s\n", options.cwd);
                printf("\tAllowing (%ld):\n", options.allow.count);
                for (size_t i = 0; i < options.allow.count; ++i)
                        printf("\t\t%s\n", options.allow.paths[i].str);
                printf("\tExcluding (%ld):\n", options.exclude.count);
                for (size_t i = 0; i < options.exclude.count; ++i)
                        printf("\t\t%s\n", options.exclude.paths[i].str);
        }

        if (optind >= argc) {
                fprintf(stderr, "Missing tagfile(s) path\n");
                ret = EXIT_FAILURE;
                goto end_opts;
        }

        for (size_t i = 0; i < (size_t)(argc - optind); ++i)
                ret = parse_tagfiles(argv[optind + i], &options);

end_opts:
        opts_free(&options);
end_free:
        free(options.allow.paths);
        free(options.exclude.paths);
end:
        return ret;
}
