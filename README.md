Mobbage - a HTTP stress test and benchmark tool
===============================================

Mobbage is a python script intended to be used as a stress testing tool for 
HTTP(S) servers and web-aware applications.  It is similar to (and directly
inspired by) siege, a HTTP load testing utility by Jeffrey Fulmer (and
available at https://github.com/JoeDog/siege).  

Mobbage, however, includes a few more bells and whistles (keepalives, http/2,
authentication,  cookiejar support, multipart/form-data uploads, etc) as well 
as the ability to provide a complex test plan via a URL job file.


## Installation

Installation is as simple as:

    pip install mobbage

This should install mobbage and all of its required Python modules (which
is only the `requests` module at this point) from PyPI.  If you _must_ have
the absolute latest and greatest, you can install directly from this repo:

    pip install https://github.com/redfin/mobbage/zipball/master

## Usage

Mobbage can be controlled either via the command line or via a specially 
constructed job file (or both; global defaults can be specified via the 
command line and overriden by variables in the job file).  

Command-line options can be grouped into these categories:

### Request control:

    URL                      URL(s) to fetch
    -f str, --jobfile str    Read job data from this file
    -F str, --urlfile str    Read url data from this file. Mutually exclusive
                             with -f
    -m str, --method str     HTTP method to use. Default is 'GET'
    -a str, --agent str      Set User-Agent request header
    -H str, --header str     Send request header in 'name:value' format. Specify
                             more than once for multiple headers
    -u str, --upload str     Upload a file via multipart/form-data POST. Must be
                             formatted as 'form_var:file_path[:content_type]'.
                             If content type isn't specified, a best guess will
                             be made based on the filename. This option can be
                             specified more than once. Forces method to be POST
    -i, --insecure           Disable SSL certificate validation
    -k, --nokeepalive        Disable keep-alive requests
    -c str, --cookiejar str  Path to Unix/Netscape formatted cookie jar file.
    -2, --http2              Use HTTP/2 standard (experimental).

### Authentication:

    -A str, --auth str       Auth credentials in 'username:password' format
    -T str, --authtype str   Authentication type to use: basic(default), digest

### Flow control:

    -w N, --workers N        Use this many concurrent workers. Default is 1
    -n N, --num N            Quit after exceeding this number of requests
    -t N, --time N           Quit after running for this number of seconds
    -b N, --bytes N          Quit after for this number of seconds
    -e N, --errors N         Quit after encountering this many errors
    -d N, --delay N          Pause N ms after each request. Default is 0
    -r, --random             Fetch URLs in random order instead of sequentially

### Output control (mutually exclusive):

    -q, --quiet              Suppress all output
    -j, --json               Format results as JSON
    -s, --csv                Format results as CSV
    -p, --progress           Show progress bar
    -V, --verbose            Print verbose worker output

### Reporting:

    -g str, --graphite str   Graphite host to use, defined as 'server[:port]'
    -P str, --prefix str     Prefix for graphite metrics. Default is 'mobbage'

### Information:

    -v, --version            Show version and quit
    -h, --help               Show this help text

## URL File Format:

The url file is a newline delimited list of URLs (and optionally 
methods and POST idata) compatible with the siege file format, e.g.:

    http://www.site1.com
    http://www.site1.com GET
    http://www.site2.org POST foo=bar&bin=baz

## Job file format

The job file is a JSON formatted array of objects, with each object 
representing a single URL to test.  Options for each test should be specified 
in key:value form for each test object, using the same key name as the long 
versions of the option names from the command line.  Options that are honored 
in the job objects are:
 * url
 * num
 * data
 * delay
 * method
 * agent
 * header
 * upload 
 * insecure
 * nokeepalive
 * auth
 * authtype

Options not specified in a job object will inherit values set on the command 
line, and default values otherwise.  The "header" and "upload" should be
specified as JSON arrays of strings.

### Example file format:
    [
        { "url": "http://www.foo.com", "count": 100,
          "header": ["host:www.bar.com", "accept-language:en-us"] },
        { "url": "http://www.google.com/search?q=lmgtfy",
          "agent": "lulzBot/0.1", "delay": 50 },
        { "url": "http://www.bar.com", "method": "POST",
          "data": "field1=boo&field2=baz" },
        { "url": "http://www.myhost.com", "count": 10,
          "upload": ["file1:/tmp/foo.txt", "file2:/tmp/bar.zip"] }
    ]

## Caveats

 * HTTP/2 support is implemented via the Python `hyper` module, which is
in early alpha.  There _will_ be bugs.  To enable HTTP/2 support, you must
first installed hyper: `pip install hyper`.
 * URLs cannot be specified on the command line if you are using a job control
file
 * User agents can be specified either via the `-a` option or by specifying a 
`user-agent` header manually via the `-H` option.  If both are specified, the
value set by the `-H` option takes precedence.
 * Keep-alives can be disabled either via the `-k` flag or by setting the 
`connection` header to "close".  If you use the `-k` flag, however, you will
overwrite anything previously specified in the `connection` header.
 * Cookie jars (specified via `-c`) are read and maintained on a per-worker
basis, and not written back to the orignal file on disk.  So, cookies that are
set in each worker can be used for the next request to the same resource, but
are not shared amongst workers, and cannot be persisted to subsequent mobbage
sessions.
 * All of the output control flags are mutually exclusive (so you can't have
a progress bar with CSV output, for example).
 * Reports sent to a Graphite carbon server are done via UDP, and thus will
not produce an error if the carbon server is unreachable.  If the carbon 
server's port is not specified, it is assumed to be 2003.

## Want to help?

Patches are always welcome!
See [the contributing guide](CONTRIBUTING.md) to get started.
