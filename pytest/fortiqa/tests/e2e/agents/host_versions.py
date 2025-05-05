windows_tf_modules: list = ['windows2016', 'windows2019', 'windows2022']

supported_csps: list = ['aws', 'gcp', 'azure']

# Make sure linux_tf_modules is the last list of modules
linux_tf_modules: list = [
    'alpine3.19',
    'ubuntu1604', 'ubuntu1804', 'ubuntu2004', 'ubuntu2204', 'ubuntu2404',
    'rhel8.9', 'rhel9.4',
    'rocky8.9', 'rocky9.4',
    'oraclelinux89', 'oraclelinux93',
    'opensuse_leap_15.6',
    'amazonlinux2', 'amazonlinux2023',
    'centos_stream_8', 'centos_stream_9', 'centos_stream_10',
    'sles12.sp5', 'sles15.sp6',
    'debian10', 'debian11', 'debian12',
]

linux_tf_modules = list(filter(None, linux_tf_modules))

windows_tf_modules = list(filter(None, windows_tf_modules))

all_tf_modules: list = linux_tf_modules + windows_tf_modules
