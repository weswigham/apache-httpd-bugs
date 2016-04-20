class FileTable
    @@db = {}

    def self.db
        return @@db
    end

    def initialize(release)
        @release = release
        @@db[@release] = {}
    end
    
    def has_file(filepath)
        return !@@db[@release][filepath].nil?
    end

    def get_file(filepath)
        if has_file(filepath)
            return @@db[@release][filepath]
        else
            file = ReleaseFile.new(filepath, @release)
            @@db[@release][filepath] = file
            return file
        end
    end

    def each
        @@db[@release].each do |path, file|
            yield file
        end
    end
end

class ReleaseFile
    attr_accessor :filepath, :churn, :num_commits, :sloc, :bugs, :enhancements, :blocker_sev_bugs, :major_sev_bugs, :minor_sev_bugs, :critical_sev_bugs, :normal_sev_bugs, :trivial_sev_bugs, :regressions, :vulnerabilities
    def initialize(path, release)
        @release = release
        @filepath = path
        @churn = 0
        @num_commits = 0
        @sloc = 0
        @bugs = 0
        @enhancements = 0
        @blocker_sev_bugs = 0
        @major_sev_bugs = 0
        @minor_sev_bugs = 0
        @critical_sev_bugs = 0
        @normal_sev_bugs = 0
        @trivial_sev_bugs = 0
        @regressions = 0
        @vulnerabilities = 0
    end
end
