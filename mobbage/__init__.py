#!/usr/bin/env python3

VERSION=0.2

import argparse
import collections
import datetime
import json
import mimetypes
import os
import random
import requests
import requests.auth
import signal
import socket
import sys
import threading
import time

# Python version-specific module names
if sys.version[0] == '3':
    from http.cookiejar import MozillaCookieJar
    from urllib.parse import parse_qs
    import queue 
else:
    from cookielib import MozillaCookieJar
    from urlparse import parse_qs
    import Queue as queue

# Get command line arguments and print usage/help statement
def get_args():
    
    url_file_help = '\n  '.join([
        'URL File Format:\n',
        'The url file is a newline delimited list of URLs (and optionally ',
        'methods and POST idata) compatible with the siege file format, e.g.:',
        '  http://www.site1.com',
        '  http://www.site1.com GET',
        '  http://www.site2.org POST foo=bar&bin=baz',
        '\nJob File Format:\n',
        'The job file is a JSON formatted array of objects, with each object',
        'representing a single URL to test.  Options that are honored in the',
        'job objects are:' ,
        '    url, method, agent, header, upload, insecure, nokeepalive,',
        '    num, delay\n',
        'Options not specified in a job object will inherit values set on',
        'the command line, and default values otherwise. The "header" and',
        '"upload" should be specified as arrays.',
        'Example file contents:',
        '  [',
        '      { "url": "http://www.foo.com", "count": 100,',
        '        "header": ["host:www.bar.com", "accept-language:en-us"] },',
        '      { "url": "http://www.google.com/search?q=lmgtfy",',
        '        "agent": "lulzBot/0.1", "delay": 50 },',
        '      { "url": "http://www.bar.com", "method": "POST",',
        '        "data": "field1=boo&field2=baz" },',
        '      { "url": "http://www.myhost.com", "count": 10,',
        '        "upload": ["file1:/tmp/foo.txt", "file2:/tmp/bar.zip"] }',
        '  ]',
    ])

    parser = argparse.ArgumentParser(
        prog="mobbage",
        description="Mobbage: A HTTP stress tester",
        formatter_class=CustomFormat,
        epilog=url_file_help,
        add_help=False)
    
    group1 = parser.add_argument_group("Request control")
    group1.add_argument("urls", metavar="URL", nargs="*",
        help="URL(s) to fetch")
    group1.add_argument("-f", "--jobfile", metavar="str", 
        type=argparse.FileType("rt"),
        help="Read job data from this file")
    group1.add_argument("-F", "--urlfile", metavar="str", 
        type=argparse.FileType("rt"),
        help="Read url data from this file.  Mutually exclusive with -f")
    group1.add_argument("-m", "--method", metavar="str", default="GET",
        help="HTTP method to use.  Default is 'GET'")
    group1.add_argument("-a", "--agent", metavar="str", 
        default="mobbage/{}".format(VERSION),
        help="Set User-Agent request header")
    group1.add_argument("-H", "--header", metavar="str", action="append",
        default=[], help="""Send request header in 'name:value' format. 
          Specify more than once for multiple headers""")
    group1.add_argument("-u", "--upload", metavar="str", action="append",
        default=[],  help="""Upload a file via multipart/form-data POST. 
        Must be formatted as 'form_var:file_path[:content_type]'.
        If content type isn't specified, a best guess will be made based 
        on the filename. This option can be specified more than once.  Forces
        method to be POST""")
    group1.add_argument("-i", "--insecure", action="store_true",
        help="Disable SSL certificate validation")
    group1.add_argument("-k", "--nokeepalive", action="store_true",
        help="Disable keep-alive requests")
    group1.add_argument("-c", "--cookiejar", metavar="str",
        help="Path to Unix/Netscape formatted cookie jar file.")
    group1.add_argument("-2", "--http2", action="store_true",
        help="Use HTTP/2 standard (experimental).")

    group2 = parser.add_argument_group("Authentication")
    group2.add_argument("-A", "--auth", metavar="str", 
        help="Auth credentials in 'username:password' format")
    group2.add_argument("-T", "--authtype", metavar="str", default="basic",
        help="Authentication type to use: basic(default), digest")

    group3 = parser.add_argument_group("Flow control")
    group3.add_argument("-w", "--workers", metavar="N", type=int, default=1,
        help="Use this many concurrent workers. Default is 1")
    group3.add_argument("-n", "--num", metavar="N", type=int, default=0,
        help="Quit after exceeding this number of requests")
    group3.add_argument("-t", "--time", metavar="N", type=int, default=0,
        help="Quit after running for this number of seconds")
    group3.add_argument("-b", "--bytes", metavar="N", type=int, default=0,
        help="Quit after  for this number of seconds")
    group3.add_argument("-e", "--errors", metavar="N", type=int, default=0,
        help="Quit after encountering this many errors")
    group3.add_argument("-d", "--delay", metavar="N", type=int, default=0,
        help="Pause N ms after each request. Default is 0")
    group3.add_argument("-r", "--random", action="store_true",
        help="Fetch URLs in random order instead of sequentially")

    group4 = parser.add_argument_group("Output control (mutually exclusive)")
    group4.add_argument("-q", "--quiet", action="store_true",
        help="Suppress all output")
    group4.add_argument("-j", "--json", action="store_true",
        help="Format results as JSON")
    group4.add_argument("-s", "--csv", action="store_true",
        help="Format results as CSV")
    group4.add_argument("-p", "--progress", action="store_true",
        help="Show progress bar")
    group4.add_argument("-V", "--verbose", action="store_true",
        help="Print verbose worker output")

    group5 = parser.add_argument_group("Reporting")
    group5.add_argument("-g", "--graphite", metavar="str",
        help="Graphite host to use, defined as 'server[:port]'")
    group5.add_argument("-P", "--prefix", default="mobbage", metavar="str",
        help="Prefix for graphite metrics.  Default is 'mobbage'")

    group6 = parser.add_argument_group("Information")
    group6.add_argument("-v", "--version", action="version",
        version='mobbage {}'.format(VERSION), help="Show version and quit")
    group6.add_argument("-h", "--help", action="help",
        help="Show this help text")

    args = parser.parse_args()

    # Show our help text if we haven't defined any urls or an url file
    if args.urls == [] and args.jobfile is None and args.urlfile is None:
        parser.print_help()
        sys.exit(1)

    # And also show it if we have specified both, because that's just silly
    if args.urls and (args.jobfile or args.urlfile):
        error("Positional urls and job/URL files are mutually exclusive.", 
            parser)
    if args.jobfile and args.urlfile:
        error("Job/URL files are mutually exclusive.", parser)

    # Make sure more than one output flag hasn't been set
    if(args.json + args.csv + args.progress > 1):
        error("Output control options are mutually exclusive.", parser)

    # Try and include HTTP/2 support, if requested
    if args.http2:
        try:
            from hyper.contrib import HTTP20Adapter
        except ImportError:
            error("Can't find HTTP/2 module: hyper. Please install.")
        except Exception as e:
            error("Can't import HTTP/2 module: hyper: " + str(e))

    return args


# Custom formatter so that our help text doesn't look like doo-doo
class CustomFormat(argparse.HelpFormatter):
    def __init__(self, prog, indent_increment=2,
            max_help_position=30, width=None):
        argparse.HelpFormatter.__init__(self, prog, indent_increment=2,
            max_help_position=30, width=None)

    def _fill_text(self, text, width, indent):
        return ''.join([indent + line for line in text.splitlines(True)])

# Helper class to allow access to dict keys via dot notation
class DotDict(dict):
    def __getattr__(self, attr):
        return self.get(attr)
    __setattr__= dict.__setitem__
    __delattr__= dict.__delitem__

    def __getstate__(self):
        return self

    def __setstate__(self, state):
        self.update(state)
        self.__dict__ = self


# Our worker queue, since a simple Queue object wouldn't cut it for our needs
class WorkerQueue():
    # Set ourselves up with some empty variables to start
    def __init__(self, is_random=False):
        self.jobs = []
        self.lock = threading.Lock()
        self.position = 0
        self.length = 0
        self.is_random = is_random
        self.num_finished = 0

    # Put data on our queue and increment its size
    def put(self, job_dict, args):

        if not isinstance(job_dict, dict):
            raise Exception("Jobs must be submitted as dictionaries")

        # Make this a DotDict to make accessing keys cleaner
        job = DotDict(job_dict)

        # URL is the only thing required in each datum
        if not "url" in job:
            raise Exception("No url specified")

        # Add an http prefix onto our URL, if its not
        # explicitly defined as HTTP/HTTPS
        if job.url[:4] != "http":
            job.url = "http://" + job.url

        # Other options can be inherited from those specified
        # on the command line.  Do some sanity checking here, too

        # Set our method (GET, POST, etc)
        if not "method" in job:
            job.method = args.method

        # Read in our job delay... 
        try:
            job.delay = (job.delay/1000.0
                if 'delay' in job else args.delay/1000.0)
        except ValueError:
            raise Exception("Delay must be an integer")

        # ... and set our query parameters
        job.params = {}
        job.orig_url = job.url
        if "?" in job.url:
            job.url, query_string = job.url.split("?", 1)
            job.params = parse_qs(query_string)

        # ... and our authentication (if any)
        if "auth" in job:
            job.auth = job.auth.split(":",1)
        elif args.auth:
            job.auth = args.auth.split(":",1)
        else:
            job.auth = None
        job.auth = None

        if "authtype" in job:
            job.authtype = job.authtype
        else:
            job.authtype = args.authtype

        if job.auth and len(job.auth) == 1:
            raise Exception("Credentials must be in username:password format")
        if job.authtype not in ("basic","digest"):
            raise Exception("Auth type must be one of: basic, digest")

        # ... and our job counter
        try:
            job.count = int(job.count) if 'count' in job else args.num
        except ValueError:
            raise Exception("Count must be an integer")

        # ... and cookies!
        try:
            cj = MozillaCookieJar()
            if "cookiejar" in job:
                cj.load(job.cookiejar)
                job.cookiejar = cj
            elif args.cookiejar:
                cj.load(args.cookiejar)
                job.cookiejar = cj
            else:
                job.cookiejar = None
        except Exception as e:
            raise Exception("Unable to load cookie jar: {}".format(e))

        # ... our insecure option
        if not "insecure" in job:
            job.insecure = args.insecure
        else:
            if not isinstance(job.insecure, bool):
                raise Exception("Insecure flag must be a boolean")

        # Fix up method case; RFCs 7230/1 state method is case sensitive,
        # but all current recognized methods are upper case, soooo...
        job.method = job.method.upper()

        # Now turn our list of header key:value pairs into
        # the dict that the requests module requires
        header_list = []

        # Coalesce headers from the command line and the job/url file, if any
        if "headers" in job:
            if not isinstance(job.headers, list):
                raise Exception("Headers must be in list form")
            header_list = job.headers + args.header
        else:
            header_list = args.header

        # Convert our list of colon-delimited k:v pairs to a dict
        header_dict = {}
        for kv in header_list:
            try:
                key, val = map(strip, ':'.split(kv))
                header_dict[key.lower()] = val 
            except:
                raise Exception(
                    "'{}' header must be in 'key:value' format".format(kv)
                )

        # Set our user agent here, since it is a header too
        if not "user-agent" in header_dict:
            if "agent" in job:
                header_dict["user-agent"] = job.agent
            else:
                header_dict["user-agent"] = args.agent

        # Override the connection header if user has requests keep-alives
        # be disabled
        if args.nokeepalive:
            header_dict["connection"] = "close"

        # Overwrite the header list with the header dict for requests
        job.headers = header_dict

        # Set up POST file reads
        upload_files = (job.upload + args.upload 
            if "upload" in job else args.upload)
        job.upload = []
        for file_data in upload_files:
            i = file_data.split(":", 2)
            if len(i) < 2:
                raise Exception("Upload files must be in "
                    "form_var:file_path[:content_type] format")
            file_var, file_path = i
            
            # Make sure our file exists
            try:
                open(file_path, "rb")
            except:
                raise Exception(
                    "{} is not a readable file!".format(file_path)
                )

            # Now guess the mime type if we weren't provided one explicitly
            if len(i) == 3:
                mime_type = i[2]
            else:
                mime_type = (mimetypes.guess_type(file_path)[0] 
                    or 'application/octet-stream')

            # Now stick the file data in our upload list
            job.upload.append((file_var, file_path, mime_type))

        # Override the method if we have multipart files to POST
        if job.upload:
            job.method = "POST"

        # Now insert the job into our work queue
        with self.lock:
            self.jobs.append(job)
            self.length += 1

    # Fetch data from our queue in a round-robin fashion (without
    # actually removing anything from the queue).  Block if the queue is
    # empty
    def get(self):

        with self.lock:
            if self.length > 0:
                # Get a random position if we were instantiated that way
                if self.is_random:
                    self.position = random.randint(0, self.length - 1)

                # We create a deep copy of the data here to prevent any
                # thread-unsafe hijinks while accessing it
                job = self.jobs[self.position]

                # If this data type has a counter embedded in it, 
                # decrement it, and if it has reached zero, delete it 
                # from the work list
                if job.count > 0:
                    job.count -= 1
                    
                    if job.count == 0:
                        del(self.jobs[self.position])
                        self.length -= 1

                # Move our position counter to the next available job.  If 
                # we have reached the end of the queue, wrap around to 
                # the start of the queue
                if not self.is_random:
                    self.position += 1
                    if self.position >= self.length:
                        self.position = 0

                return job

            # If the work queue is empty, then we should start shutting
            # things down
            else:
                self.num_finished += 1
                return None


    # Delete all remaining items from the job queue
    def purge(self):
        with self.lock:
            self.length = 0
            self.jobs = []

    # Return true if the queue is empty; false otherwise
    def is_empty(self):
        with self.lock:
            return self.length == 0

    # Return the number of worker waiting for input
    def finished_workers(self):
        with self.lock:
            return self.num_finished


# Our worker thread, responsible for doing all of the heavy lifting
class WorkerThread(threading.Thread):
    def __init__(self, work_queue, result_queue, http2):
        threading.Thread.__init__(self)
        self.work_queue = work_queue
        self.result_queue = result_queue
        self.http2 = http2

    # Code that gets executed once the thread is launched
    def run(self):
        while True:
            job = self.work_queue.get()

            # If the queue is empty, then our work is done
            if job is None:
                return

            # Set up our Requests session.
            sess = requests.session()

            # Mount our HTTP/2 transport adapter, if requested
            if self.http2:
                from hyper.contrib import HTTP20Adapter
                sess.mount('https://', HTTP20Adapter())

            # Fire off the request and trap any errors that pop up
            start = time.clock()
            try:

                # Build our multipart file list, if necessary
                upload_files = []
                for file_data in job.upload:
                    file_var, file_path, mime_type = file_data
                    file_obj = open(file_path, "rb")
                    file_name = file_path.split("/")[-1]

                    upload_files.append(
                        (file_var, (file_name, file_obj, mime_type))
                    )

                # Add authentication (if any)
                auth = None
                if job.auth:
                    if job.authtype == "digest":
                        auth = requests.auth.HTTPDigestAuth(job.auth)
                    else:
                        auth = requests.auth.HTTPBasicAuth(job.auth)

                # Now fire off our request!
                resp = sess.request(
                    job.method,
                    job.url,
                    params=job.params,
                    data=job.data,
                    headers=job.headers,
                    files=upload_files,
                    auth=auth,
                    cookies=job.cookiejar,
                    verify=not job.insecure

                )
                resp.raise_for_status()

                # Record the time spent on the request
                elapsed = time.clock() - start

                # Now send the results off to our parent thread.  Note that we 
                # read the actual length of the content instead of using the
                # content-length response header, since consuming the content
                # is required for keepalives and we might as well do it here
                self.result_queue.put(DotDict({
                    'url':  job.orig_url,
                    'code': resp.status_code,
                    'time': elapsed,
                    'size': len(resp.content)
                }))

            # Catch any errors here, be they client-side errors (i.e.
            # a mal-formed url passed to the requests module) or server
            # side errors
            except Exception as e:
                try:
                    err_code = resp.status_code
                except:
                    err_code = 400

                elapsed = time.clock() - start
                self.result_queue.put(DotDict({
                    'url': job.orig_url,
                    'code': err_code,
                    'time': elapsed,
                    'size': 0,
                    'error': e
                }))
                        

            # Now sleep for the specified inter-request time (can be 0)
            time.sleep(job.delay)
    

# Throw a fatal error message and then exit
def error(msg, parser=False):
    print("ERROR: " + msg)
    if parser:
        parser.print_help()
    sys.exit(1)
    

# Convert bytes to human readable
def bytes_to_human(num, suffix='B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1000.0:
            return "{:03.1f}{}{}".format(num, unit, suffix)
        num /= 1000.0
    return "{:.1f}{}{}".format(num, 'Y', suffix)


# Convert number to fixed-length human readable format
def num_to_human(num):
    if num < 1000:
        return num
    for unit in ['','K','M','B','T']:
        if abs(num) < 1000.0:
            return "{:.2f}{}".format(num, unit)
        num /= 1000.0
    return "{:.1d}{}{}".format(num, 'T', suffix)


# Convert seconds to hh:mm:ss
def seconds_to_human(sec):
    m, s = map(int, divmod(sec, 60))
    h, m = map(int, divmod(m, 60))
    return "{:02d}:{:02d}:{:02d}".format(h, m, s)


# Print if not quiet
def output(msg):
    if not quiet:
        print(msg)


# Main function -- start of program execution
def main():

    # Handle ctrl-c
    global running
    running = True
    def handle_sigint(*args):
        global running
        running = False
    signal.signal(signal.SIGINT, handle_sigint)

    # Snatch commandline arguments
    args = get_args()

    # Make us quieter, if requested
    global quiet
    quiet = args.quiet

    # Initialize our worker and result queues
    work_queue = WorkerQueue(args.random)
    result_queue = queue.Queue()

    # Populate our work queue from our file, if we got that
    # particular runtime argument
    if args.jobfile:
        try:
            json_data = json.loads(args.jobfile.read())
        except ValueError as e:
            error("JSON Error: {}".format(e))

        if not isinstance(json_data, list):
            error("Outer JSON data container must be a list/array")

        try:
            for data in json_data:
                work_queue.put(data, args)
        except Exception as e:
            error("Data error: {}\n{}".format(e, str(data)))

    # Also try reading files from a siege-style URL file
    # formatted something like: <URL> [method] [query string]
    elif args.urlfile:
        for line in args.urlfile:
            url_opts = line.rstrip().split(None, 2)
            data = {} if len(url_opts) < 3 else parse_qs(url_opts[2])
            method = "GET" if len(url_opts) < 2 else url_opts[1]
            work_queue.put({"url": url_opts[0], "method": method, 
                "data": data}, args)

    # Otherwise populate it using the URLs specified on the command-line
    else:
        try:
            for url in args.urls:
                work_queue.put({"url": url}, args)
        except Exception as e:
            error(str(e))

    # Now start the worker threads up
    if not args.quiet and not args.csv and not args.json:
        output("Starting mobbage with {} worker{}.".format(args.workers,
            "s" if args.workers > 1 else ""))
    threads = []
    for i in range(args.workers):
        thread = WorkerThread(work_queue, result_queue, args.http2)
        thread.start()
        threads.append(thread)
        
    # Stop parameters
    time_start   = time.time()
    num_requests = 0
    time_running = 0
    num_errors   = 0

    # Various metrics to collect
    inf          = float('+inf')
    min_time     = inf
    max_time     = 0
    total_time   = 0
    min_size     = inf
    max_size     = 0
    total_size   = 0
    result_codes = collections.defaultdict(int)

    prog_update  = time_start
    prog_length  = 0

    # Poll our results queue until one of the specified stop
    # conditions is met

    while ((not args.time or time_running < args.time)
            and (not args.num or num_requests < args.num)
            and (not args.errors or num_errors < args.errors)
            and running):

        # Perform a blocking get, but time out after 1 second
        try:
            # Pull a result off our result queue and process it
            result = result_queue.get(True, 1)
            num_requests += 1
            result_codes[result.code] += 1

            # Print our verbose output if requested
            if args.verbose:
                print "Code: {}, Size: {}, Time: {:d}ms, URL: {}".format(
                    result.code,
                    bytes_to_human(result.size),
                    int(result.time*1000),
                    result.url)

            if result.error:
                num_errors += 1
            else:
                # Woo, successful result, compile some data about it
                if result.size < min_size:
                    min_size = result.size
                if result.size > max_size:
                    max_size = result.size
                total_size += result.size

                if result.time < min_time:
                    min_time = result.time
                if result.time > max_time:
                    max_time = result.time
                total_time += result.time

        except queue.Empty:
            # If our result queue is empty and all of our workers are
            # idle, then we are done.  Break out!
            if work_queue.finished_workers() == args.workers:
                break

        time_running = time.time() - time_start

        # Print our progress bar if requested
        if args.progress and prog_update < time.time() - 1:
            
            progress = ("[{:%Y-%m-%d %H:%M:%S}] Elapsed: {}, "
                "{} requests, {} errors, {}\r").format(
                    datetime.datetime.now(),
                    seconds_to_human(time_running),
                    num_to_human(num_requests),
                    num_to_human(num_errors),
                    bytes_to_human(total_size)
            )

            sys.stderr.write((" " * prog_length)+"\r")
            sys.stderr.write(progress)
            sys.stderr.flush()
            
            prog_length = len(progress)+1
            prog_update = time.time()

    # Purge our work queue to force our worker threads to exit and then
    # wait for the threads to join
    work_queue.purge()
    for thread in threads:
        thread.join()

    # Clean up after our progress bar if it was being used
    if args.progress:
        sys.stderr.write((" " * prog_length)+"\r")
        sys.stderr.flush()

    # Do some post-process calculations
    num_success = num_requests - num_errors
    if min_time == inf: 
        min_time = 0
    if min_size == inf: 
        min_size = 0
    min_time = int(min_time * 1000.0) 
    max_time = int(max_time * 1000.0)
    ms_running = int(time_running * 1000.0)
    avg_time = int(total_time * 1000.0 / num_success) if num_success else 0
    avg_size = total_size / num_success if num_success else 0
    availability = num_success * 100.0 / num_requests
    bps = total_size / time_running
    concurrency = num_requests / time_running

    # Print our results in the requested format, like CSV...
    if args.csv:
        print((
            "ms_running,requests,success,errors,avail,min_ms,avg_ms,max_ms,"
            "min_bytes,avg_bytes,max_bytes,total_bytes,bps,concurrency\n"
            "{},{},{},{},{:.2f},{},{},{},"
            "{},{:.2f},{},{},{:.2f},{:.2f}\n"
        ).format(
                ms_running, num_requests, num_success, num_errors,
                availability, min_time, avg_time, max_time, min_size, 
                avg_size, max_size, total_size, bps, concurrency
        ))

    # Or JSON...
    elif args.json:
        print((
            '{{"ms_running": {}, "requests": {}, "success": {}, '
            '"errors": {}, "avail": {:.2f}, "min_ms": {}, "avg_ms": {}, '
            '"max_ms": {}, "min_bytes": {}, "avg_bytes": {}, "max_bytes": {}, '
            '"total_bytes": {}, "bps": {:.2f}, "concurrency": {:.2f}, {}}}'
        ).format(
            ms_running, num_requests, num_success, num_errors,
            availability, min_time, avg_time, max_time, min_size, 
            avg_size, max_size, total_size, bps, concurrency,
            ', '.join(['"code_{}": {}'.format(k, result_codes[k]) 
                for k in sorted(result_codes, key=result_codes.get, reverse=True)]
            )
        ))

    # Otherwise just print some nicely formatted text to stdout
    else:

        print((
            "Results:\n"
            "    Total time:        {}\n"
            "    Requests:          {}\n"
            "    Successes:         {}\n"
            "    Errors:            {}\n"
            "    Availability       {:.2f}%\n"
            "    Minimum time:      {:d}ms\n"
            "    Average time:      {:d}ms\n"
            "    Maximum time:      {:d}ms\n"
            "    Minimum size:      {}\n"
            "    Average size:      {}\n"
            "    Maximum size:      {}\n"
            "    Total data:        {}\n"
            "    Average data rate: {}/s\n"
            "    Concurrency:       {:.2f}\n\n"
            "    Results by return code\n"
            "        {}\n"
        ).format(
            seconds_to_human(time_running),
            num_requests,
            num_success,
            num_errors,
            num_success * 100.0 / num_requests,
            min_time,
            avg_time,
            max_time,
            bytes_to_human(min_size),
            bytes_to_human(avg_size),
            bytes_to_human(max_size),
            bytes_to_human(total_size),
            bytes_to_human(total_size/time_running),
            num_requests / time_running,
            '\n'.ljust(8).join(["{}:{: >13}".format(k, result_codes[k]) 
                for k in sorted(result_codes, key=result_codes.get, reverse=True)]
            )
        ))

    # Send stats to our graphite server if requested
    if args.graphite:
        try:
            graphite_addr = args.graphite.split(":", 1)
            if len(graphite_addr) == 1:
                graphite_addr = (graphite_addr[0], 2003)
            else:
                graphite_addr = (graphite_addr[0], int(graphite_addr[0]))
        except:
            error("Graphite address must be in 'server[:port]' format")

        now = int(time.time())
        metrics = [
            "ms_running %d %s" % (time_running*1000, now),
            "requests %s %s" % (num_requests, now),
            "success %s %s" % (num_success, now),
            "errors %s %s" % (num_errors, now),
            "avail %.2f %s" % (availability, now),
            "min_ms %d %s" % (min_time, now),
            "avg_ms %d %s" % (avg_time, now),
            "max_ms %d %s" % (max_time, now),
            "min_bytes %d %s" % (min_size, now),
            "avg_bytes %d %s" % (avg_size, now),
            "max_bytes %d %s" % (max_size, now),
            "total_bytes %d %s" % (total_size, now),
            "bps %.2f %s" % (bps, now),
            "concurrency %.2f %s" % (concurrency, now)
        ]
        prefix = args.prefix + "."
        metric_str = prefix + ("\n%s" % prefix).join(metrics) + "\n"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(metric_str, graphite_addr)
        except Exception as e:
            error("Unable to send to graphite: %s" % e)

if __name__ == "__main__":
    main()

