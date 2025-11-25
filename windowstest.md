Successfully installed medusa-security-2025.2.0.13  
PS C:\WINDOWS\system32> pip install shellcheck --debug  
Using pip 25.3 from C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip (python 3.11)  
Non-user install because site-packages writeable  
Created temporary directory: C:\Users\rossc\AppData\Local\Temp\pip-build-tracker-b4qqyxoc  
Initialized build tracking at C:\Users\rossc\AppData\Local\Temp\pip-build-tracker-b4qqyxoc  
Created build tracker: C:\Users\rossc\AppData\Local\Temp\pip-build-tracker-b4qqyxoc  
Entered build tracker: C:\Users\rossc\AppData\Local\Temp\pip-build-tracker-b4qqyxoc  
Created temporary directory: C:\Users\rossc\AppData\Local\Temp\pip-install-p7p54fy3  
Created temporary directory: C:\Users\rossc\AppData\Local\Temp\pip-ephem-wheel-cache-mfvfzvc2  
1 location(s) to search for versions of shellcheck:  
* [https://pypi.org/simple/shellcheck/](https://pypi.org/simple/shellcheck/)  
Fetching project page and analyzing links: [https://pypi.org/simple/shellcheck/](https://pypi.org/simple/shellcheck/)  
Getting page [https://pypi.org/simple/shellcheck/](https://pypi.org/simple/shellcheck/)  
Found index url [https://pypi.org/simple/](https://pypi.org/simple/)  
Looking up "[https://pypi.org/simple/shellcheck/](https://pypi.org/simple/shellcheck/)" in the cache  
Request header has "max_age" as 0, cache bypassed  
No cache entry available  
Starting new HTTPS connection (1): [pypi.org:443](http://pypi.org:443)  
[https://pypi.org:443](https://pypi.org:443) "GET /simple/shellcheck/ HTTP/1.1" 404 13  
Status code 404 not in (200, 203, 300, 301, 308)  
Could not fetch URL [https://pypi.org/simple/shellcheck/](https://pypi.org/simple/shellcheck/): 404 Client Error: Not Found for url: [https://pypi.org/simple/shellcheck/](https://pypi.org/simple/shellcheck/) - skipping  
Skipping link: not a file: [https://pypi.org/simple/shellcheck/](https://pypi.org/simple/shellcheck/)  
Given no hashes to check 0 links for project 'shellcheck': discarding no candidates  
ERROR: Could not find a version that satisfies the requirement shellcheck (from versions: none)  
Remote version of pip: 25.3  
Local version of pip:  25.3  
Was pip installed by pip? True  
Removed build tracker: 'C:\\Users\\rossc\\AppData\\Local\\Temp\\pip-build-tracker-b4qqyxoc'  
┌─────────────────────────────── Traceback (most recent call last) ────────────────────────────────┐  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_vendor\resolvelib\resolvers\r │  
│ esolution.py:434 in resolve                                                                      │  
│                                                                                                  │  
│   431 │   │   ]                                                                                  │  
│   432 │   │   for r in requirements:                                                             │  
│   433 │   │   │   try:                                                                           │  
│ > 434 │   │   │   │   self._add_to_criteria(self.state.criteria, r, parent=None)                 │  
│   435 │   │   │   except RequirementsConflicted as e:                                            │  
│   436 │   │   │   │   raise ResolutionImpossible(e.criterion.information) from e                 │  
│   437                                                                                            │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │   max_rounds = 200000                                                                        │ │  
│ │            r = SpecifierRequirement('shellcheck')                                            │ │  
│ │ requirements = [SpecifierRequirement('shellcheck')]                                          │ │  
│ │         self = <pip._vendor.resolvelib.resolvers.resolution.Resolution object at             │ │  
│ │                0x000002454F691850>                                                           │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_vendor\resolvelib\resolvers\r │  
│ esolution.py:151 in _add_to_criteria                                                             │  
│                                                                                                  │  
│   148 │   │   │   incompatibilities=incompatibilities,                                           │  
│   149 │   │   )                                                                                  │  
│   150 │   │   if not criterion.candidates:                                                       │  
│ > 151 │   │   │   raise RequirementsConflicted(criterion)                                        │  
│   152 │   │   criteria[identifier] = criterion                                                   │  
│   153 │                                                                                          │  
│   154 │   def _remove_information_from_criteria(                                                 │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │          criteria = {}                                                                       │ │  
│ │         criterion = Criterion((SpecifierRequirement('shellcheck'), via=None))                │ │  
│ │        identifier = 'shellcheck'                                                             │ │  
│ │ incompatibilities = []                                                                       │ │  
│ │       information = [                                                                        │ │  
│ │                     │   RequirementInformation(                                              │ │  
│ │                     │   │   requirement=SpecifierRequirement('shellcheck'),                  │ │  
│ │                     │   │   parent=None                                                      │ │  
│ │                     │   )                                                                    │ │  
│ │                     ]                                                                        │ │  
│ │           matches = <pip._internal.resolution.resolvelib.found_candidates.FoundCandidates    │ │  
│ │                     object at 0x000002454F693090>                                            │ │  
│ │            parent = None                                                                     │ │  
│ │       requirement = SpecifierRequirement('shellcheck')                                       │ │  
│ │              self = <pip._vendor.resolvelib.resolvers.resolution.Resolution object at        │ │  
│ │                     0x000002454F691850>                                                      │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
└──────────────────────────────────────────────────────────────────────────────────────────────────┘  
RequirementsConflicted: Requirements conflict: SpecifierRequirement('shellcheck')  
  
The above exception was the direct cause of the following exception:  
  
┌─────────────────────────────── Traceback (most recent call last) ────────────────────────────────┐  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\resolution\resolveli │  
│ b\resolver.py:99 in resolve                                                                      │  
│                                                                                                  │  
│    96 │   │                                                                                      │  
│    97 │   │   try:                                                                               │  
│    98 │   │   │   limit_how_complex_resolution_can_be = 200000                                   │  
│ >  99 │   │   │   result = self._result = resolver.resolve(                                      │  
│   100 │   │   │   │   collected.requirements, max_rounds=limit_how_complex_resolution_can_be     │  
│   101 │   │   │   )                                                                              │  
│   102                                                                                            │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │              check_supported_wheels = True                                                   │ │  
│ │                           collected = CollectedRootRequirements(                             │ │  
│ │                                       │   requirements=[                                     │ │  
│ │                                       │   │   SpecifierRequirement('shellcheck')             │ │  
│ │                                       │   ],                                                 │ │  
│ │                                       │   constraints={},                                    │ │  
│ │                                       │   user_requested={'shellcheck': 0}                   │ │  
│ │                                       )                                                      │ │  
│ │                               error = DistributionNotFound('No matching distribution found   │ │  
│ │                                       for shellcheck')                                       │ │  
│ │ limit_how_complex_resolution_can_be = 200000                                                 │ │  
│ │                            provider = <pip._internal.resolution.resolvelib.provider.PipProv… │ │  
│ │                                       object at 0x000002454F692090>                          │ │  
│ │                            reporter = <pip._internal.resolution.resolvelib.reporter.PipRepo… │ │  
│ │                                       object at 0x000002454F692450>                          │ │  
│ │                            resolver = <pip._vendor.resolvelib.resolvers.resolution.Resolver  │ │  
│ │                                       object at 0x000002454F692DD0>                          │ │  
│ │                           root_reqs = [                                                      │ │  
│ │                                       │   <InstallRequirement object: shellcheck             │ │  
│ │                                       editable=False>                                        │ │  
│ │                                       ]                                                      │ │  
│ │                                self = <pip._internal.resolution.resolvelib.resolver.Resolver │ │  
│ │                                       object at 0x000002454F5BFDD0>                          │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_vendor\resolvelib\resolvers\r │  
│ esolution.py:601 in resolve                                                                      │  
│                                                                                                  │  
│   598 │   │   │   `max_rounds` argument.                                                         │  
│   599 │   │   """                                                                                │  
│   600 │   │   resolution = Resolution(self.provider, self.reporter)                              │  
│ > 601 │   │   state = resolution.resolve(requirements, max_rounds=max_rounds)                    │  
│   602 │   │   return _build_result(state)                                                        │  
│   603                                                                                            │  
│   604                                                                                            │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │   max_rounds = 200000                                                                        │ │  
│ │ requirements = [SpecifierRequirement('shellcheck')]                                          │ │  
│ │   resolution = <pip._vendor.resolvelib.resolvers.resolution.Resolution object at             │ │  
│ │                0x000002454F691850>                                                           │ │  
│ │         self = <pip._vendor.resolvelib.resolvers.resolution.Resolver object at               │ │  
│ │                0x000002454F692DD0>                                                           │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_vendor\resolvelib\resolvers\r │  
│ esolution.py:436 in resolve                                                                      │  
│                                                                                                  │  
│   433 │   │   │   try:                                                                           │  
│   434 │   │   │   │   self._add_to_criteria(self.state.criteria, r, parent=None)                 │  
│   435 │   │   │   except RequirementsConflicted as e:                                            │  
│ > 436 │   │   │   │   raise ResolutionImpossible(e.criterion.information) from e                 │  
│   437 │   │                                                                                      │  
│   438 │   │   # The root state is saved as a sentinel so the first ever pin can have             │  
│   439 │   │   # something to backtrack to if it fails. The root state is basically               │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │   max_rounds = 200000                                                                        │ │  
│ │            r = SpecifierRequirement('shellcheck')                                            │ │  
│ │ requirements = [SpecifierRequirement('shellcheck')]                                          │ │  
│ │         self = <pip._vendor.resolvelib.resolvers.resolution.Resolution object at             │ │  
│ │                0x000002454F691850>                                                           │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
└──────────────────────────────────────────────────────────────────────────────────────────────────┘  
ResolutionImpossible: [RequirementInformation(requirement=SpecifierRequirement('shellcheck'), parent=None)]  
  
The above exception was the direct cause of the following exception:  
  
┌─────────────────────────────── Traceback (most recent call last) ────────────────────────────────┐  
│ in _run_module_as_main:198                                                                       │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │   alter_argv = False                                                                         │ │  
│ │         code = <code object <module> at 0x000002454B746140, file "C:\Program                 │ │  
│ │                Files\Python311\Scripts\pip.exe\__main__.py", line 1>                         │ │  
│ │ main_globals = {                                                                             │ │  
│ │                │   '__name__': '__main__',                                                   │ │  
│ │                │   '__doc__': None,                                                          │ │  
│ │                │   '__package__': '',                                                        │ │  
│ │                │   '__loader__': <zipimporter object "C:\Program                             │ │  
│ │                Files\Python311\Scripts\pip.exe\">,                                           │ │  
│ │                │   '__spec__': ModuleSpec(name='__main__', loader=<zipimporter object        │ │  
│ │                "C:\Program Files\Python311\Scripts\pip.exe\">, origin='C:\\Program           │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__main__.py'),                            │ │  
│ │                │   '__annotations__': {},                                                    │ │  
│ │                │   '__builtins__': <module 'builtins' (built-in)>,                           │ │  
│ │                │   '__file__': 'C:\\Program                                                  │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__main__.py',                             │ │  
│ │                │   '__cached__': 'C:\\Program                                                │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__pycache__\\__main__.cpython-311.pyc',   │ │  
│ │                │   're': <module 're' from 'C:\\Program                                      │ │  
│ │                Files\\Python311\\Lib\\re\\__init__.py'>,                                     │ │  
│ │                │   ... +2                                                                    │ │  
│ │                }                                                                             │ │  
│ │     mod_name = '__main__'                                                                    │ │  
│ │     mod_spec = ModuleSpec(name='__main__', loader=<zipimporter object "C:\Program            │ │  
│ │                Files\Python311\Scripts\pip.exe\">, origin='C:\\Program                       │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__main__.py')                             │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│ in _run_code:88                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │       cached = 'C:\\Program                                                                  │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__pycache__\\__main__.cpython-311.pyc'    │ │  
│ │         code = <code object <module> at 0x000002454B746140, file "C:\Program                 │ │  
│ │                Files\Python311\Scripts\pip.exe\__main__.py", line 1>                         │ │  
│ │        fname = 'C:\\Program Files\\Python311\\Scripts\\pip.exe\\__main__.py'                 │ │  
│ │ init_globals = None                                                                          │ │  
│ │       loader = <zipimporter object "C:\Program Files\Python311\Scripts\pip.exe\">            │ │  
│ │     mod_name = '__main__'                                                                    │ │  
│ │     mod_spec = ModuleSpec(name='__main__', loader=<zipimporter object "C:\Program            │ │  
│ │                Files\Python311\Scripts\pip.exe\">, origin='C:\\Program                       │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__main__.py')                             │ │  
│ │     pkg_name = ''                                                                            │ │  
│ │  run_globals = {                                                                             │ │  
│ │                │   '__name__': '__main__',                                                   │ │  
│ │                │   '__doc__': None,                                                          │ │  
│ │                │   '__package__': '',                                                        │ │  
│ │                │   '__loader__': <zipimporter object "C:\Program                             │ │  
│ │                Files\Python311\Scripts\pip.exe\">,                                           │ │  
│ │                │   '__spec__': ModuleSpec(name='__main__', loader=<zipimporter object        │ │  
│ │                "C:\Program Files\Python311\Scripts\pip.exe\">, origin='C:\\Program           │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__main__.py'),                            │ │  
│ │                │   '__annotations__': {},                                                    │ │  
│ │                │   '__builtins__': <module 'builtins' (built-in)>,                           │ │  
│ │                │   '__file__': 'C:\\Program                                                  │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__main__.py',                             │ │  
│ │                │   '__cached__': 'C:\\Program                                                │ │  
│ │                Files\\Python311\\Scripts\\pip.exe\\__pycache__\\__main__.cpython-311.pyc',   │ │  
│ │                │   're': <module 're' from 'C:\\Program                                      │ │  
│ │                Files\\Python311\\Lib\\re\\__init__.py'>,                                     │ │  
│ │                │   ... +2                                                                    │ │  
│ │                }                                                                             │ │  
│ │  script_name = None                                                                          │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ in <module>:7                                                                                    │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\cli\main.py:80 in    │  
│ main                                                                                             │  
│                                                                                                  │  
│   77 │   │   logger.debug("Ignoring error %s when setting locale", e)                            │  
│   78 │   command = create_command(cmd_name, isolated=("--isolated" in cmd_args))                 │  
│   79 │                                                                                           │  
│ > 80 │   return command.main(cmd_args)                                                           │  
│   81                                                                                             │  
│                                                                                                  │  
│ ┌──────────────────────────────────────── locals ─────────────────────────────────────────┐      │  
│ │     args = ['install', 'shellcheck', '--debug']                                         │      │  
│ │ cmd_args = ['shellcheck', '--debug']                                                    │      │  
│ │ cmd_name = 'install'                                                                    │      │  
│ │  command = <pip._internal.commands.install.InstallCommand object at 0x000002454C952D10> │      │  
│ └─────────────────────────────────────────────────────────────────────────────────────────┘      │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\cli\base_command.py: │  
│ 159 in main                                                                                      │  
│                                                                                                  │  
│   156 │   def main(self, args: list[str]) -> int:                                                │  
│   157 │   │   try:                                                                               │  
│   158 │   │   │   with self.main_context():                                                      │  
│ > 159 │   │   │   │   return self._main(args)                                                    │  
│   160 │   │   finally:                                                                           │  
│   161 │   │   │   logging.shutdown()                                                             │  
│   162                                                                                            │  
│                                                                                                  │  
│ ┌────────────────────────────────────── locals ───────────────────────────────────────┐          │  
│ │ args = ['shellcheck', '--debug']                                                    │          │  
│ │ self = <pip._internal.commands.install.InstallCommand object at 0x000002454C952D10> │          │  
│ └─────────────────────────────────────────────────────────────────────────────────────┘          │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\cli\base_command.py: │  
│ 238 in _main                                                                                     │  
│                                                                                                  │  
│   235 │   │   │   │   )                                                                          │  
│   236 │   │   │   │   options.cache_dir = None                                                   │  
│   237 │   │                                                                                      │  
│ > 238 │   │   return self._run_wrapper(level_number, options, args)                              │  
│   239 │                                                                                          │  
│   240 │   def handler_map(self) -> dict[str, Callable[[Values, list[str]], None]]:               │  
│   241 │   │   """                                                                                │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │ always_enabled_features = set()                                                              │ │  
│ │                    args = ['shellcheck']                                                     │ │  
│ │            level_number = 10                                                                 │ │  
│ │                 options = <Values at 0x2454f42ad10: {'help': None, 'debug_mode': True,       │ │  
│ │                           'isolated_mode': False, 'require_venv': False, 'python': None,     │ │  
│ │                           'verbose': 0, 'version': None, 'quiet': 0, 'log': None,            │ │  
│ │                           'no_input': False, 'keyring_provider': 'auto', 'proxy': '',        │ │  
│ │                           'retries': 5, 'timeout': 15, 'exists_action': [], 'trusted_hosts': │ │  
│ │                           [], 'cert': None, 'client_cert': None, 'cache_dir':                │ │  
│ │                           'c:\\users\\rossc\\appdata\\local\\pip\\cache',                    │ │  
│ │                           'disable_pip_version_check': False, 'no_color': False,             │ │  
│ │                           'no_python_version_warning': False, 'features_enabled': [],        │ │  
│ │                           'deprecated_features_enabled': [], 'resume_retries': 5,            │ │  
│ │                           'requirements': [], 'constraints': [], 'build_constraints': [],    │ │  
│ │                           'ignore_dependencies': False, 'pre': False, 'editables': [],       │ │  
│ │                           'dry_run': False, 'target_dir': None, 'platforms': None,           │ │  
│ │                           'python_version': None, 'implementation': None, 'abis': None,      │ │  
│ │                           'use_user_site': False, 'root_path': None, 'prefix_path': None,    │ │  
│ │                           'src_dir': 'C:\\WINDOWS\\system32\\src', 'upgrade': None,          │ │  
│ │                           'upgrade_strategy': 'only-if-needed', 'force_reinstall': None,     │ │  
│ │                           'ignore_installed': None, 'ignore_requires_python': None,          │ │  
│ │                           'build_isolation': True, 'use_pep517': True, 'check_build_deps':   │ │  
│ │                           False, 'override_externally_managed': None, 'config_settings':     │ │  
│ │                           None, 'compile': True, 'warn_script_location': True,               │ │  
│ │                           'warn_about_conflicts': True, 'format_control':                    │ │  
│ │                           FormatControl(set(), set()), 'prefer_binary': False,               │ │  
│ │                           'require_hashes': False, 'progress_bar': 'on', 'root_user_action': │ │  
│ │                           'warn', 'index_url': '[https://pypi.org/simple](https://pypi.org/simple)',                    │ │  
│ │                           'extra_index_urls': [], 'no_index': False, 'find_links': [],       │ │  
│ │                           'json_report_file': None, 'dependency_groups': [], 'no_clean':     │ │  
│ │                           False}>                                                            │ │  
│ │                    self = <pip._internal.commands.install.InstallCommand object at           │ │  
│ │                           0x000002454C952D10>                                                │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\cli\base_command.py: │  
│ 104 in _run_wrapper                                                                              │  
│                                                                                                  │  
│   101 │   │                                                                                      │  
│   102 │   │   if options.debug_mode:                                                             │  
│   103 │   │   │   rich_traceback.install(show_locals=True)                                       │  
│ > 104 │   │   │   return _inner_run()                                                            │  
│   105 │   │                                                                                      │  
│   106 │   │   try:                                                                               │  
│   107 │   │   │   status = _inner_run()                                                          │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │         args = ['shellcheck']                                                                │ │  
│ │ level_number = 10                                                                            │ │  
│ │      options = <Values at 0x2454f42ad10: {'help': None, 'debug_mode': True, 'isolated_mode': │ │  
│ │                False, 'require_venv': False, 'python': None, 'verbose': 0, 'version': None,  │ │  
│ │                'quiet': 0, 'log': None, 'no_input': False, 'keyring_provider': 'auto',       │ │  
│ │                'proxy': '', 'retries': 5, 'timeout': 15, 'exists_action': [],                │ │  
│ │                'trusted_hosts': [], 'cert': None, 'client_cert': None, 'cache_dir':          │ │  
│ │                'c:\\users\\rossc\\appdata\\local\\pip\\cache', 'disable_pip_version_check':  │ │  
│ │                False, 'no_color': False, 'no_python_version_warning': False,                 │ │  
│ │                'features_enabled': [], 'deprecated_features_enabled': [], 'resume_retries':  │ │  
│ │                5, 'requirements': [], 'constraints': [], 'build_constraints': [],            │ │  
│ │                'ignore_dependencies': False, 'pre': False, 'editables': [], 'dry_run':       │ │  
│ │                False, 'target_dir': None, 'platforms': None, 'python_version': None,         │ │  
│ │                'implementation': None, 'abis': None, 'use_user_site': False, 'root_path':    │ │  
│ │                None, 'prefix_path': None, 'src_dir': 'C:\\WINDOWS\\system32\\src',           │ │  
│ │                'upgrade': None, 'upgrade_strategy': 'only-if-needed', 'force_reinstall':     │ │  
│ │                None, 'ignore_installed': None, 'ignore_requires_python': None,               │ │  
│ │                'build_isolation': True, 'use_pep517': True, 'check_build_deps': False,       │ │  
│ │                'override_externally_managed': None, 'config_settings': None, 'compile':      │ │  
│ │                True, 'warn_script_location': True, 'warn_about_conflicts': True,             │ │  
│ │                'format_control': FormatControl(set(), set()), 'prefer_binary': False,        │ │  
│ │                'require_hashes': False, 'progress_bar': 'on', 'root_user_action': 'warn',    │ │  
│ │                'index_url': '[https://pypi.org/simple](https://pypi.org/simple)', 'extra_index_urls': [], 'no_index':   │ │  
│ │                False, 'find_links': [], 'json_report_file': None, 'dependency_groups': [],   │ │  
│ │                'no_clean': False}>                                                           │ │  
│ │         self = <pip._internal.commands.install.InstallCommand object at 0x000002454C952D10>  │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\cli\base_command.py: │  
│ 98 in _inner_run                                                                                 │  
│                                                                                                  │  
│    95 │   def _run_wrapper(self, level_number: int, options: Values, args: list[str]) -> int:    │  
│    96 │   │   def _inner_run() -> int:                                                           │  
│    97 │   │   │   try:                                                                           │  
│ >  98 │   │   │   │   return self.run(options, args)                                             │  
│    99 │   │   │   finally:                                                                       │  
│   100 │   │   │   │   self.handle_pip_version_check(options)                                     │  
│   101                                                                                            │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │    args = ['shellcheck']                                                                     │ │  
│ │ options = <Values at 0x2454f42ad10: {'help': None, 'debug_mode': True, 'isolated_mode':      │ │  
│ │           False, 'require_venv': False, 'python': None, 'verbose': 0, 'version': None,       │ │  
│ │           'quiet': 0, 'log': None, 'no_input': False, 'keyring_provider': 'auto', 'proxy':   │ │  
│ │           '', 'retries': 5, 'timeout': 15, 'exists_action': [], 'trusted_hosts': [], 'cert': │ │  
│ │           None, 'client_cert': None, 'cache_dir':                                            │ │  
│ │           'c:\\users\\rossc\\appdata\\local\\pip\\cache', 'disable_pip_version_check':       │ │  
│ │           False, 'no_color': False, 'no_python_version_warning': False, 'features_enabled':  │ │  
│ │           [], 'deprecated_features_enabled': [], 'resume_retries': 5, 'requirements': [],    │ │  
│ │           'constraints': [], 'build_constraints': [], 'ignore_dependencies': False, 'pre':   │ │  
│ │           False, 'editables': [], 'dry_run': False, 'target_dir': None, 'platforms': None,   │ │  
│ │           'python_version': None, 'implementation': None, 'abis': None, 'use_user_site':     │ │  
│ │           False, 'root_path': None, 'prefix_path': None, 'src_dir':                          │ │  
│ │           'C:\\WINDOWS\\system32\\src', 'upgrade': None, 'upgrade_strategy':                 │ │  
│ │           'only-if-needed', 'force_reinstall': None, 'ignore_installed': None,               │ │  
│ │           'ignore_requires_python': None, 'build_isolation': True, 'use_pep517': True,       │ │  
│ │           'check_build_deps': False, 'override_externally_managed': None, 'config_settings': │ │  
│ │           None, 'compile': True, 'warn_script_location': True, 'warn_about_conflicts': True, │ │  
│ │           'format_control': FormatControl(set(), set()), 'prefer_binary': False,             │ │  
│ │           'require_hashes': False, 'progress_bar': 'on', 'root_user_action': 'warn',         │ │  
│ │           'index_url': '[https://pypi.org/simple](https://pypi.org/simple)', 'extra_index_urls': [], 'no_index': False, │ │  
│ │           'find_links': [], 'json_report_file': None, 'dependency_groups': [], 'no_clean':   │ │  
│ │           False}>                                                                            │ │  
│ │    self = <pip._internal.commands.install.InstallCommand object at 0x000002454C952D10>       │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\cli\req_command.py:8 │  
│ 5 in wrapper                                                                                     │  
│                                                                                                  │  
│    82 │   │   │   configure_tempdir_registry(self.tempdir_registry)                              │  
│    83 │   │                                                                                      │  
│    84 │   │   try:                                                                               │  
│ >  85 │   │   │   return func(self, options, args)                                               │  
│    86 │   │   except PreviousBuildDirError:                                                      │  
│    87 │   │   │   # This kind of conflict can occur when the user passes an explicit             │  
│    88 │   │   │   # build directory with a pre-existing folder. In that case we do               │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │    args = ['shellcheck']                                                                     │ │  
│ │ options = <Values at 0x2454f42ad10: {'help': None, 'debug_mode': True, 'isolated_mode':      │ │  
│ │           False, 'require_venv': False, 'python': None, 'verbose': 0, 'version': None,       │ │  
│ │           'quiet': 0, 'log': None, 'no_input': False, 'keyring_provider': 'auto', 'proxy':   │ │  
│ │           '', 'retries': 5, 'timeout': 15, 'exists_action': [], 'trusted_hosts': [], 'cert': │ │  
│ │           None, 'client_cert': None, 'cache_dir':                                            │ │  
│ │           'c:\\users\\rossc\\appdata\\local\\pip\\cache', 'disable_pip_version_check':       │ │  
│ │           False, 'no_color': False, 'no_python_version_warning': False, 'features_enabled':  │ │  
│ │           [], 'deprecated_features_enabled': [], 'resume_retries': 5, 'requirements': [],    │ │  
│ │           'constraints': [], 'build_constraints': [], 'ignore_dependencies': False, 'pre':   │ │  
│ │           False, 'editables': [], 'dry_run': False, 'target_dir': None, 'platforms': None,   │ │  
│ │           'python_version': None, 'implementation': None, 'abis': None, 'use_user_site':     │ │  
│ │           False, 'root_path': None, 'prefix_path': None, 'src_dir':                          │ │  
│ │           'C:\\WINDOWS\\system32\\src', 'upgrade': None, 'upgrade_strategy':                 │ │  
│ │           'only-if-needed', 'force_reinstall': None, 'ignore_installed': None,               │ │  
│ │           'ignore_requires_python': None, 'build_isolation': True, 'use_pep517': True,       │ │  
│ │           'check_build_deps': False, 'override_externally_managed': None, 'config_settings': │ │  
│ │           None, 'compile': True, 'warn_script_location': True, 'warn_about_conflicts': True, │ │  
│ │           'format_control': FormatControl(set(), set()), 'prefer_binary': False,             │ │  
│ │           'require_hashes': False, 'progress_bar': 'on', 'root_user_action': 'warn',         │ │  
│ │           'index_url': '[https://pypi.org/simple](https://pypi.org/simple)', 'extra_index_urls': [], 'no_index': False, │ │  
│ │           'find_links': [], 'json_report_file': None, 'dependency_groups': [], 'no_clean':   │ │  
│ │           False}>                                                                            │ │  
│ │    self = <pip._internal.commands.install.InstallCommand object at 0x000002454C952D10>       │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\commands\install.py: │  
│ 388 in run                                                                                       │  
│                                                                                                  │  
│   385 │   │   │                                                                                  │  
│   386 │   │   │   self.trace_basic_info(finder)                                                  │  
│   387 │   │   │                                                                                  │  
│ > 388 │   │   │   requirement_set = resolver.resolve(                                            │  
│   389 │   │   │   │   reqs, check_supported_wheels=not options.target_dir                        │  
│   390 │   │   │   )                                                                              │  
│   391                                                                                            │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │                                args = ['shellcheck']                                         │ │  
│ │                       build_tracker = <pip._internal.operations.build.build_tracker.BuildTr… │ │  
│ │                                       object at 0x000002454F614D90>                          │ │  
│ │                           directory = <repr-error 'Attempted to access deleted path:         │ │  
│ │                                       C:\\Users\\rossc\\AppData\\Local\\Temp\\pip-install-p… │ │  
│ │                              finder = <pip._internal.index.package_finder.PackageFinder      │ │  
│ │                                       object at 0x000002454F5EB5D0>                          │ │  
│ │ installing_into_current_environment = True                                                   │ │  
│ │                             options = <Values at 0x2454f42ad10: {'help': None, 'debug_mode': │ │  
│ │                                       True, 'isolated_mode': False, 'require_venv': False,   │ │  
│ │                                       'python': None, 'verbose': 0, 'version': None,         │ │  
│ │                                       'quiet': 0, 'log': None, 'no_input': False,            │ │  
│ │                                       'keyring_provider': 'auto', 'proxy': '', 'retries': 5, │ │  
│ │                                       'timeout': 15, 'exists_action': [], 'trusted_hosts':   │ │  
│ │                                       [], 'cert': None, 'client_cert': None, 'cache_dir':    │ │  
│ │                                       'c:\\users\\rossc\\appdata\\local\\pip\\cache',        │ │  
│ │                                       'disable_pip_version_check': False, 'no_color': False, │ │  
│ │                                       'no_python_version_warning': False,                    │ │  
│ │                                       'features_enabled': [], 'deprecated_features_enabled': │ │  
│ │                                       [], 'resume_retries': 5, 'requirements': [],           │ │  
│ │                                       'constraints': [], 'build_constraints': [],            │ │  
│ │                                       'ignore_dependencies': False, 'pre': False,            │ │  
│ │                                       'editables': [], 'dry_run': False, 'target_dir': None, │ │  
│ │                                       'platforms': None, 'python_version': None,             │ │  
│ │                                       'implementation': None, 'abis': None, 'use_user_site': │ │  
│ │                                       False, 'root_path': None, 'prefix_path': None,         │ │  
│ │                                       'src_dir': 'C:\\WINDOWS\\system32\\src', 'upgrade':    │ │  
│ │                                       None, 'upgrade_strategy': 'only-if-needed',            │ │  
│ │                                       'force_reinstall': None, 'ignore_installed': None,     │ │  
│ │                                       'ignore_requires_python': None, 'build_isolation':     │ │  
│ │                                       True, 'use_pep517': True, 'check_build_deps': False,   │ │  
│ │                                       'override_externally_managed': None,                   │ │  
│ │                                       'config_settings': None, 'compile': True,              │ │  
│ │                                       'warn_script_location': True, 'warn_about_conflicts':  │ │  
│ │                                       True, 'format_control': FormatControl(set(), set()),   │ │  
│ │                                       'prefer_binary': False, 'require_hashes': False,       │ │  
│ │                                       'progress_bar': 'on', 'root_user_action': 'warn',      │ │  
│ │                                       'index_url': '[https://pypi.org/simple](https://pypi.org/simple)',                │ │  
│ │                                       'extra_index_urls': [], 'no_index': False,             │ │  
│ │                                       'find_links': [], 'json_report_file': None,            │ │  
│ │                                       'dependency_groups': [], 'no_clean': False}>           │ │  
│ │                            preparer = <pip._internal.operations.prepare.RequirementPreparer  │ │  
│ │                                       object at 0x000002454F6292D0>                          │ │  
│ │                                 req = <InstallRequirement object: shellcheck editable=False> │ │  
│ │                                reqs = [                                                      │ │  
│ │                                       │   <InstallRequirement object: shellcheck             │ │  
│ │                                       editable=False>                                        │ │  
│ │                                       ]                                                      │ │  
│ │                            resolver = <pip._internal.resolution.resolvelib.resolver.Resolver │ │  
│ │                                       object at 0x000002454F5BFDD0>                          │ │  
│ │                                self = <pip._internal.commands.install.InstallCommand object  │ │  
│ │                                       at 0x000002454C952D10>                                 │ │  
│ │                             session = <pip._internal.network.session.PipSession object at    │ │  
│ │                                       0x000002454B798910>                                    │ │  
│ │                       target_python = <pip._internal.models.target_python.TargetPython       │ │  
│ │                                       object at 0x000002454F5F22C0>                          │ │  
│ │                     target_temp_dir = None                                                   │ │  
│ │                target_temp_dir_path = None                                                   │ │  
│ │                    upgrade_strategy = 'to-satisfy-only'                                      │ │  
│ │                         wheel_cache = <pip._internal.cache.WheelCache object at              │ │  
│ │                                       0x000002454F5BF150>                                    │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
│                                                                                                  │  
│ C:\Users\rossc\AppData\Roaming\Python\Python311\site-packages\pip\_internal\resolution\resolveli │  
│ b\resolver.py:108 in resolve                                                                     │  
│                                                                                                  │  
│   105 │   │   │   │   cast("ResolutionImpossible[Requirement, Candidate]", e),                   │  
│   106 │   │   │   │   collected.constraints,                                                     │  
│   107 │   │   │   )                                                                              │  
│ > 108 │   │   │   raise error from e                                                             │  
│   109 │   │   except ResolutionTooDeep:                                                          │  
│   110 │   │   │   raise ResolutionTooDeepError from None                                         │  
│   111                                                                                            │  
│                                                                                                  │  
│ ┌─────────────────────────────────────────── locals ───────────────────────────────────────────┐ │  
│ │              check_supported_wheels = True                                                   │ │  
│ │                           collected = CollectedRootRequirements(                             │ │  
│ │                                       │   requirements=[                                     │ │  
│ │                                       │   │   SpecifierRequirement('shellcheck')             │ │  
│ │                                       │   ],                                                 │ │  
│ │                                       │   constraints={},                                    │ │  
│ │                                       │   user_requested={'shellcheck': 0}                   │ │  
│ │                                       )                                                      │ │  
│ │                               error = DistributionNotFound('No matching distribution found   │ │  
│ │                                       for shellcheck')                                       │ │  
│ │ limit_how_complex_resolution_can_be = 200000                                                 │ │  
│ │                            provider = <pip._internal.resolution.resolvelib.provider.PipProv… │ │  
│ │                                       object at 0x000002454F692090>                          │ │  
│ │                            reporter = <pip._internal.resolution.resolvelib.reporter.PipRepo… │ │  
│ │                                       object at 0x000002454F692450>                          │ │  
│ │                            resolver = <pip._vendor.resolvelib.resolvers.resolution.Resolver  │ │  
│ │                                       object at 0x000002454F692DD0>                          │ │  
│ │                           root_reqs = [                                                      │ │  
│ │                                       │   <InstallRequirement object: shellcheck             │ │  
│ │                                       editable=False>                                        │ │  
│ │                                       ]                                                      │ │  
│ │                                self = <pip._internal.resolution.resolvelib.resolver.Resolver │ │  
│ │                                       object at 0x000002454F5BFDD0>                          │ │  
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │  
└──────────────────────────────────────────────────────────────────────────────────────────────────┘  
DistributionNotFound: No matching distribution found for shellcheck  
PS C:\WINDOWS\system32>