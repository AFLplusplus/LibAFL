// jif.cc
// Heavily based off headless_example.cc from chromium project: https://chromium.googlesource.com/chromium/src/+/master/headless/app/headless_example.cc
// Original copyright notice follows:

// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is the C++ Executor
// It provides three external C functions:
// LLVMFuzzerTestOneInput - the main entry point for the fuzzer
// LLVMFuzzerInitialize - called once before any other fuzzer function
// get_js_coverage - called to get the JS coverage data

#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <fstream>
#include <cctype>

#include <signal.h>

#include "base/bind.h"
#include "base/base64.h"
#include "base/command_line.h"
#include "base/memory/weak_ptr.h"
#include "base/task/thread_pool.h"
#include "base/values.h"
#include "build/build_config.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "headless/public/devtools/domains/page.h"
#include "headless/public/devtools/domains/runtime.h"
#include "headless/public/devtools/domains/profiler.h"
#include "headless/public/headless_browser.h"
#include "headless/public/headless_devtools_client.h"
#include "headless/public/headless_devtools_target.h"
#include "headless/public/headless_web_contents.h"

#include "ui/gfx/geometry/size.h"
#include "v8/include/v8.h"

bool VERBOSE_MODE = std::getenv("JIF_VERBOSE") != nullptr;
size_t MAX_TESTCASE_LENGTH = 1024 * 10;


// This class contains the main application logic, i.e., waiting for a page to
// load and printing its DOM. Note that browser initialization happens outside
// this class.
class JIF : public headless::HeadlessWebContents::Observer,
                        public headless::page::Observer {
 public:
  JIF(headless::HeadlessBrowser* browser,
                  headless::HeadlessWebContents* web_contents);
  ~JIF() override;

  // headless::HeadlessWebContents::Observer implementation:
  void DevToolsTargetReady() override;

  // headless::page::Observer implementation:
  void OnLoadEventFired(
      const headless::page::LoadEventFiredParams& params) override;

  // Tip: Observe headless::inspector::ExperimentalObserver::OnTargetCrashed to
  // be notified of renderer crashes.


  void OnDomFetched(std::unique_ptr<headless::runtime::EvaluateResult> result);

  void OnJavascriptDialogOpening(
    const headless::page::JavascriptDialogOpeningParams& params) override;

  // The headless browser instance. Owned by the headless library. See main().
  headless::HeadlessBrowser* browser_;
  // Our tab. Owned by |browser_|.
  headless::HeadlessWebContents* web_contents_;
  // The DevTools client used to control the tab.
  std::unique_ptr<headless::HeadlessDevToolsClient> devtools_client_;
  std::unique_ptr<headless::HeadlessDevToolsClient> devtools_client_js;
  // A helper for creating weak pointers to this class.
  base::WeakPtrFactory<JIF> weak_factory_{this};
};

namespace {
JIF* jif_global = NULL;
std::mutex headless_startup_mutex;
std::mutex devtools_ready_mutex;
std::mutex page_loaded_mutex;
std::mutex js_load_mutex;
std::mutex harness_done_mutex;
std::mutex precise_coverage_started_mutex;
std::mutex precise_coverage_completed_mutex;
std::mutex precise_coverage_stopped_mutex;
std::condition_variable precise_coverage_started_cv;
std::condition_variable precise_coverage_completed_cv;
std::condition_variable precise_coverage_stopped_cv;
std::condition_variable headless_startup_cv;
std::condition_variable devtools_ready_cv;
std::condition_variable page_loaded_cv;
std::condition_variable js_load_cv;
std::condition_variable harness_done_cv;
std::string processed_test_case = "";
headless::HeadlessWebContents* web_contents_js = nullptr;
scoped_refptr<base::SingleThreadTaskRunner> task_runner = nullptr;

bool alert_called = false;
bool initialized = false;

char* js_coverage = NULL;

}


JIF::JIF(headless::HeadlessBrowser* browser,
                                 headless::HeadlessWebContents* web_contents)
    : browser_(browser),
      web_contents_(web_contents),
      devtools_client_(headless::HeadlessDevToolsClient::Create()), 
      devtools_client_js(headless::HeadlessDevToolsClient::Create()) {
  web_contents_->AddObserver(this);
}

JIF::~JIF() {
  // Note that we shut down the browser last, because it owns objects such as
  // the web contents which can no longer be accessed after the browser is gone.
  devtools_client_->GetPage()->RemoveObserver(this);
  web_contents_->GetDevToolsTarget()->DetachClient(devtools_client_.get());
  web_contents_->RemoveObserver(this);
  browser_->Shutdown();
}

std::string base64_encode(std::string input){
  std::string output;
  std::vector<uint8_t> bytes(input.begin(), input.end());
  return base::Base64Encode(bytes);
}

// This method is called when the tab is ready for DevTools inspection.
void JIF::DevToolsTargetReady() {

  printf("DevTools Target Ready\n");

    // lock the mutex and set jif_global, then notify the condition variable
  std::lock_guard<std::mutex> lk(devtools_ready_mutex);

  // Attach our DevTools client to the tab so that we can send commands to it
  // and observe events.
  web_contents_->GetDevToolsTarget()->AttachClient(devtools_client_.get());
  web_contents_js->GetDevToolsTarget()->AttachClient(devtools_client_js.get());

  // Start observing events from DevTools's page domain. This lets us get
  // notified when the page has finished loading. Note that it is possible
  // the page has already finished loading by now. See
  // HeadlessShell::DevToolTargetReady for how to handle that case correctly.
  devtools_client_->GetPage()->AddObserver(this);
  devtools_client_->GetPage()->Enable();

  devtools_ready_cv.notify_all();
}

void JIF::OnLoadEventFired(
    const headless::page::LoadEventFiredParams& params) {
  
  if(VERBOSE_MODE) {
    printf("Loaded. DOM:\n");

  devtools_client_->GetRuntime()->Evaluate(
      "(document.doctype ? new "
      "XMLSerializer().serializeToString(document.doctype) + '\\n' : '') + "
      "document.documentElement.outerHTML",
      base::BindOnce(&JIF::OnDomFetched,
                     weak_factory_.GetWeakPtr()));
  }

  page_loaded_cv.notify_all();
  

}

void JIF::OnJavascriptDialogOpening(const headless::page::JavascriptDialogOpeningParams& params){
  printf("Javascript Dialog Opening\n");
  devtools_client_->GetPage()->HandleJavaScriptDialog(true);

  alert_called = true;
}

void JIF::OnDomFetched(
    std::unique_ptr<headless::runtime::EvaluateResult> result) {
  // Make sure the evaluation succeeded before reading the result.
  if (result->HasExceptionDetails()) {
    LOG(ERROR) << "Failed to serialize document: "
               << result->GetExceptionDetails()->GetText();
  } else {
    printf("%s\n", result->GetResult()->GetValue()->GetString().c_str());
  }
}



void OnNavigation(std::unique_ptr<headless::page::NavigateResult> result) {
  
}

void LoadURL(std::string url) {

  // Navigate to the given URL.
  auto page = jif_global->devtools_client_->GetPage();
  CHECK(page);
  page->Navigate(url, base::BindOnce(&OnNavigation));
  // onNavigation should unlock the mutex and notify the condition variable
}

// This function is called by the headless library after the browser has been
// initialized. It runs on the UI thread.
void OnHeadlessBrowserStarted(headless::HeadlessBrowser* browser) {



  printf("starting browser!\n");
  // In order to open tabs, we first need a browser context. It corresponds to a
  // user profile and contains things like the user's cookies, local storage,
  // cache, etc.
  headless::HeadlessBrowserContext::Builder context_builder =
      browser->CreateBrowserContextBuilder();

  // Here we can set options for the browser context. As an example we enable
  // incognito mode, which makes sure profile data is not written to disk.
  context_builder.SetIncognitoMode(true);

  // set locale info to en-us
  context_builder.SetAcceptLanguage("en-us");

  // Construct the context and set it as the default. The default browser
  // context is used by the Target.createTarget() DevTools command when no other
  // context is given.
  headless::HeadlessBrowserContext* browser_context = context_builder.Build();
  browser->SetDefaultBrowserContext(browser_context);


  // Open a tab (i.e., HeadlessWebContents) in the newly created browser
  // context.
  headless::HeadlessWebContents::Builder tab_builder(
      browser_context->CreateWebContentsBuilder());

  // We can set options for the opened tab here. In this example we are just
  // setting the initial URL to navigate to.
  tab_builder.SetInitialURL(GURL("about:blank"));

  // Create an instance of the example app, which will wait for the page to load
  // and print its DOM.
  headless::HeadlessWebContents* web_contents = tab_builder.Build();
  
  //second webcontents for inputs
  web_contents_js = tab_builder.Build();


  // lock the mutex and set jif_global, then notify the condition variable
  std::lock_guard<std::mutex> lk(headless_startup_mutex);
  jif_global = new JIF(browser, web_contents);

  headless_startup_cv.notify_all();


}

// convert a string to a data:text/html url where the input string is the base64 encoded content
// of the html file
std::string stringToDataUrl(std::string html_string) {
  std::string data_url = "data:text/html;base64,";
  // convert html_string to a span<const uint8_t>
  data_url.append(base64_encode(html_string));
  return data_url;
}

//TODO: exception handling lol
std::string ReadFile(std::string path){
  std::ifstream t(path);
  std::stringstream buffer;
  buffer << t.rdbuf();
  return buffer.str();
}




// OnHarnessLoaded 
void OnHarnessLoaded(std::unique_ptr<headless::runtime::EvaluateResult> result) {
  // Make sure the evaluation succeeded before reading the result.
  if (result->HasExceptionDetails()) {
    LOG(FATAL) << "Failed to evaluate function: "
               << result->GetExceptionDetails()->GetText();
  } else {
    printf("Harness Loaded\n");
  }
  js_load_cv.notify_all();
}

// loadJSFunctionUsingEvaluate
// This function is called by the harness to load a javascript function into the page
// using the Evaluate command.
void LoadHarness(std::string function) {

  printf("Entering load harness\n");


  CHECK(!initialized);

  //base64 encode the function
  std::string encoded_function = base64_encode(function);

  // Evaluate the given function in the page.

  // can we just Evaluate the string?
  jif_global->devtools_client_js->GetRuntime()->Evaluate(
      "eval(atob('" + encoded_function + "'))",
      base::BindOnce(&OnHarnessLoaded));

  // block until the function is loaded
  std::unique_lock<std::mutex> lk(js_load_mutex);
  js_load_cv.wait(lk);

  printf("Harness Loaded\n");
}

// OnHarnessFinished is called when the harness finishes.
void OnHarnessFinished(std::unique_ptr<headless::runtime::EvaluateResult> result) {
  // Make sure the evaluation succeeded before reading the result.
  if (result->HasExceptionDetails()) {
      LOG(WARNING) << " Evaluation failed: "
              << result->GetExceptionDetails()->GetText();
      processed_test_case = "";
  } else {
      if(result->GetResult()->HasValue()){
        processed_test_case = result->GetResult()->GetValue()->GetString();
      }
      else{
        LOG(FATAL) << "Harness did not return a value, curious";
      }
  }

  harness_done_cv.notify_all();
}

void OnPreciseCoverageStarted(std::unique_ptr<headless::profiler::StartPreciseCoverageResult> result) {
  precise_coverage_started_cv.notify_all();
}

extern "C" const char* get_js_coverage(){
  if(js_coverage != NULL)
    return (const char*) js_coverage;
  return "";
}

void OnPreciseCoverageCompleted(std::unique_ptr<headless::profiler::TakePreciseCoverageResult> result) {
  if(result){
    std::ostringstream os;
    os << *(result->Serialize());
    std::string json = os.str();
    //if(VERBOSE_MODE)
    //  std::cout << json << std::endl;
    // save the coverage to the global 
    CHECK(js_coverage == NULL);
    auto buffer = (char*)malloc(json.length() + 1); //please do not provide a coverage string of length INT_MAX
    CHECK(buffer);
    strcpy(buffer, json.c_str());
    js_coverage = buffer;
  } else{
    js_coverage = NULL;
  }
  precise_coverage_completed_cv.notify_all();
}

void OnPreciseCoverageStopped(void) {
  precise_coverage_stopped_cv.notify_all();
}

std::string RunTestCaseThroughHarness(std::string test_case){

    if(js_coverage != NULL){
      free(js_coverage);
      js_coverage = NULL;
    }

    // strip any non-printable characters from the test case:
    std::string ascii_test_case = "";
    for(int i = 0; i < test_case.length(); i++){
      if(isprint(test_case[i])){
        ascii_test_case.push_back(test_case[i]);
      }
    }

    //base64 encode the test case
    std::string encoded_test_case = base64_encode(ascii_test_case);
    std::string payload = "harness(atob('" + encoded_test_case + "'));";


    jif_global->devtools_client_js->GetProfiler()->Enable();

    jif_global->devtools_client_js->GetProfiler()->StartPreciseCoverage(
        // use builder to set options
        headless::profiler::StartPreciseCoverageParams::Builder()
            .SetCallCount(true)
            .SetDetailed(true)
            .Build(),
        base::BindOnce(&OnPreciseCoverageStarted));

    // wait for the precise coverage to start
    std::unique_lock<std::mutex> lk(precise_coverage_started_mutex);
    precise_coverage_started_cv.wait(lk);

    // run test case through harness

    processed_test_case = "";  

    //printf("running through eval: %s\n", payload.c_str());
    jif_global->devtools_client_js->GetRuntime()->Evaluate(
      payload,
      base::BindOnce(base::BindOnce(&OnHarnessFinished)));

    // wait for the harness to finish
    std::unique_lock<std::mutex> lk2(harness_done_mutex);
    harness_done_cv.wait(lk2);

    if(processed_test_case == ""){
      if(VERBOSE_MODE){
        printf("Harness returned the empty string. The triggering input was: %s\n", encoded_test_case.c_str());
      }
      return "";
    }


    
    // take precise coverage
    jif_global->devtools_client_js->GetProfiler()->TakePreciseCoverage(
        base::BindOnce(&OnPreciseCoverageCompleted));

    // wait for the precise coverage to finish
    std::unique_lock<std::mutex> lk3(precise_coverage_completed_mutex);
    precise_coverage_completed_cv.wait(lk3);

    // BUG: if we stop precise coverage, all future calls to start precise coverage fail
    // so we never do! 
    
    return processed_test_case;
}


// initialize signal logic
// TODO: do we only need this bc we're using a timeout executor?
void InitializeSignals(){
  // mask off SIGALARM
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  sigprocmask(SIG_BLOCK, &mask, NULL);

}


// LibFuzzer initilization function (LLVMInitialize)
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {

  CHECK(!initialized);

  // disable JIT
  static const char kJitless[] = "--jitless";
  v8::V8::SetFlagsFromString(kJitless);

  // Create a headless browser instance. There can be one of these per process
  // and it can only be initialized once.
  headless::HeadlessBrowser::Options::Builder builder(*argc, (const char **) *argv);


  // Here you can customize browser options. 
  builder.SetWindowSize(gfx::Size(800, 600));
  builder.SetSingleProcessMode(true);
  //disable the GPU (not sure how to do this)
  //builder.SetGLImplementation("desktop-gl-core-profile");
  builder.SetDisableSandbox(true);

  // Pass control to the headless library. It will bring up the browser and
  // invoke the given callback on the browser UI thread. Note: if you need to
  // pass more parameters to the callback, you can add them to the Bind() call
  // below.

  printf("starting headless main\n");

  //create a new std::thread which calls HeadlessBrowserMain
  std::thread headless_browser_main_thread(headless::HeadlessBrowserMain,
   builder.Build(), base::BindOnce(&OnHeadlessBrowserStarted) );

  headless_browser_main_thread.detach();

  printf("blocking on headless_startup_mutex\n");

  // wait on the condition variable headless_startup_cv until the headless_browser_main_thread
  // is ready and has set jif_global to a valid JIF instance
  std::unique_lock<std::mutex> lk(headless_startup_mutex);
  headless_startup_cv.wait(lk, []{return jif_global != nullptr;});

  printf("woke up. blocking on devtools_ready_mutex\n");

  // okay that worked, now we have to wait until DevTools is ready, same deal
  // as above
  std::unique_lock<std::mutex> lk2(devtools_ready_mutex);
  devtools_ready_cv.wait(lk2);

  //finally set up the task runner
  task_runner = content::GetUIThreadTaskRunner({}); // doesnt seem to make a perf difference whether we use UI or IO


  // initialize the harness
  // read the harness from argv
  std::string harness_file = "";
  // argv will contain "--harness ABC.js"
  // we want to read the ABC.js file
  for(int i = 0; i < *argc; i++){
    if(strcmp((*argv)[i], "--harness") == 0){
      harness_file = (*argv)[i+1]; //TODO: bounds checking
      break;
    }
  }

  //TODO: real error checking/handling

  CHECK(harness_file != "");

  std::string harness = ReadFile(harness_file);
  CHECK(harness != "");

  LoadHarness(harness);

  //initialize signals
  InitializeSignals();

  initialized = true;
  printf("done with init\n");

  return 0;
}




// Entrypoint for LibFuzzer/LibAFL
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {


  CHECK(initialized);
  alert_called = false;

  // make sure we have a valid example, not just a nullptr
  if(!size || !data)
    return 0;
  if(VERBOSE_MODE)
    printf("Pre-Harness: %s\n", data);

  //check length here

  // run the test case through the harness
  std::string result = RunTestCaseThroughHarness(std::string(reinterpret_cast<const char*>(data), size));


  if(VERBOSE_MODE)
    printf("Post-Harness: %s\n", result.c_str());

  // create data string URI from the processed data
  std::string url = stringToDataUrl(result);

  if(url.length() > MAX_TESTCASE_LENGTH){
    if(VERBOSE_MODE) printf("Testcase too long skipping. Encoded length %lu. Original: %s\n",url.length(), data);
    return 0;
  }
  // load the url on the task runner

  task_runner->PostTask(FROM_HERE,
                        base::BindOnce(&LoadURL, url));

  // wait on mutex and condition variable page_loaded_mutex and page_loaded_cv
  std::unique_lock<std::mutex> lk2(page_loaded_mutex);
  page_loaded_cv.wait(lk2);

  // okay, check the global variable to see if alert was called
  if(alert_called){
    printf("[!] XSS DETECTED: WE CALLED ALERT\n");
    printf("[!] XSS Payload: %s\n", data);
    return 42; // this is the magic number for JIF to stop fuzzing
  }


  return 0;
}

