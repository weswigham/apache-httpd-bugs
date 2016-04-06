$FILEDATA_IN_SQLITE = false
if $FILEDATA_IN_SQLITE
    # Bug and vulnerability data is small enough that we can keep it in memory
    # File information, however, grows too large fairly quickly
    # So we may need to keep it in a db while we work
    require 'sqlite3'
end

class FileTable
    @@db = $FILEDATA_IN_SQLITE && SQLite3::Database.new("file_info.db") || {}

    def self.db
        return @@db
    end

    def initialize(release)
        @release = case release
            when :"2.0.1" then "Release20Files"
            when :"2.2.1" then "Release22Files"
            when :"2.4.1" then "Release24Files"
        end

        if $FILEDATA_IN_SQLITE
            @@db.execute <<-SQL
                drop table if exists #{@release};
            SQL
            @@db.execute <<-SQL
                create table #{@release} (
                    filepath varchar(300),
                    churn int,
                    num_commits int,
                    sloc int,
                    bugs int,
                    enhancements int,
                    blocker_sev_bugs int,
                    major_sev_bugs int,
                    minor_sev_bugs int,
                    critical_sev_bugs int,
                    normal_sev_bugs int,
                    trivial_sev_bugs int,
                    regressions int,
                    vulnerabilities int
                );
            SQL
        else
            @@db[@release] = {}
        end
    end
    
    def has_file(filepath)
        if $FILEDATA_IN_SQLITE
            return @@db.execute "SELECT COUNT(*) FROM #{@release} WHERE filepath = ?;", filepath
        else
            return !@@db[@release][filepath].nil?
        end
    end

    
    def load_file(file)
        if $FILEDATA_IN_SQLITE
            FileTable.db.execute("SELECT * FROM #{@release} WHERE filepath = ?;", file.filepath) do |row|
                file.churn = row[1]
                file.num_commits = row[2]
                file.sloc = row[3]
                file.bugs = row[4]
                file.enhancements = row[5]
                file.blocker_sev_bugs = row[6]
                file.major_sev_bugs = row[7]
                file.minor_sev_bugs = row[8]
                file.critical_sev_bugs = row[9]
                file.normal_sev_bugs = row[10]
                file.trivial_sev_bugs = row[11]
                file.regressions = row[12]
                file.vulnerabilities = row[13]
            end
        end
    end

    def get_file(filepath)
        if $FILEDATA_IN_SQLITE
            file = ReleaseFile.new(filepath, @release)
            if has_file(filepath)
                load_file(file)
            end
            return file
        else
            if has_file(filepath)
                return @@db[@release][filepath]
            else
                file = ReleaseFile.new(filepath, @release)
                @@db[@release][filepath] = file
                return file
            end
        end
    end

    def each
        if $FILEDATA_IN_SQLITE
            rows = @@db.execute "SELECT filepath from #{@release};"
            rows.each do |row|
                yield get_file(row)
            end
        else
            @@db[@release].each do |path, file|
                yield file
            end
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

    def save
        if $FILEDATA_IN_SQLITE
            FileTable.db.execute "INSERT INTO #{@release} (filepath, churn, num_commits, sloc, bugs, enhancements, blocker_sev_bugs, major_sev_bugs, minor_sev_bugs, critical_sev_bugs, normal_sev_bugs, trivial_sev_bugs, regressions, vulnerabilities) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", @filepath, @churn, @num_commits, @sloc, @bugs, @enhancements, @blocker_sev_bugs, @major_sev_bugs, @minor_sev_bugs, @critical_sev_bugs, @normal_sev_bugs, @trivial_sev_bugs, @regressions, @vulnerabilities
        end
    end
end
