$FIRST_VERSION = :"2.0.1"
$SECOND_VERSION = :"2.2.0"
$THIRD_VERSION = :"2.4.0"

require './models/bug.rb'
require './models/release_file.rb'
require './models/vulnerability.rb'
require 'rugged'
require 'csv'
require 'open3'
require 'json'

#Load in bug data
bugs = {}
CSV.foreach("./data/bugs-2016-04-20.csv", headers: true) do |row|
    bugs[row[0]] = Bug.fromCSVRow(row)
end

#Load in vulnerability data
vulnerabilities = {}
CSV.foreach("./data/HTTPD Vulnerabilities - CVEs.csv", headers: true) do |row|
    vulnerabilities[row[0]] = Vulnerability.fromCSVRow(row)
end

CSV.foreach("./data/HTTPD Vulnerabilities - CVEs to Fixes.csv", headers: true) do |row|
    if vulnerabilities[row[0]] && row[4]
        vulnerabilities[row[0]].fix_hashes.push(row[4])
    end
end

releases = {}

# This is just to ignore most documentation bugs
def should_ignore_file(path)
    if path =~ /^CHANGES$/ || path =~ /^STATUS$/ || path =~ /^docs\//
        return true
    end
    return false
end

def update_file_bugs(files, bug, c)
    GC.start()
    # For every change in this commit
    c.diff(c.parents.first).each_patch do |patch|
        GC.start()
        delta = patch.delta
        # If it's a modification change
        if delta.modified?
            filepath = delta.old_file[:path]
            # And the path to the changed file isn't to be ignored
            if !should_ignore_file(filepath)
                # Then update that file's status with more churn and bug data
                file = files.get_file(filepath)
                file.bugs += 1
                sev = case bug.severity.downcase
                    when "enhancement" then "enhancements"
                    when "blocker" then "blocker_sev_bugs"
                    when "major" then "major_sev_bugs"
                    when "minor" then "minor_sev_bugs"
                    when "normal" then "normal_sev_bugs"
                    when "critical" then "critical_sev_bugs"
                    when "trivial" then "trivial_sev_bugs"
                    when "regression" then "regressions"
                    # An unknown severity - print it, for reference, then return nil
                    else puts bug.severity.downcase
                end
                if sev
                    file.send("#{sev}=", file.send(sev) + 1)
                end
            end
        end
    end
end

# TODO: Declone from the above
def update_file_churn(files, c)
    GC.start()
    # For every change in this commit
    begin
        c.diff(c.parents.first).each_patch do |patch|
            GC.start()
            delta = patch.delta
            # If it's a modification change
            if delta.modified?
                filepath = delta.old_file[:path]
                # And the path to the changed file isn't to be ignored
                if !should_ignore_file(filepath)
                    # Then update that file's status with more churn and bug data
                    file = files.get_file(filepath)
                    churn = patch.additions + patch.deletions
                    file.churn += churn
                    file.num_commits += 1
                end
            end
        end
    rescue Rugged::NoMemError
        puts "Rugged went OOM reading patchset with sha #{c.tree_id}"
    end
end

# TODO: Declone from the above
def update_file_vulnerabilities(files, c)
    # For every change in this commit
    c.diff(c.parents.first).each_patch do |patch|
        delta = patch.delta
        # If it's a modification change
        if delta.modified?
            filepath = delta.old_file[:path]
            # And the path to the changed file isn't to be ignored
            if !should_ignore_file(filepath)
                # Then update that file's status with more churn and bug data
                file = files.get_file(filepath)
                file.vulnerabilities += 1
            end
        end
    end
end

def count_sloc(releases, tag)
    repo = Rugged::Repository.new('../httpd');
    releases[tag] ||= FileTable.new(tag)
    puts "Checking out tag #{tag} to calculate sloc..."
    repo.checkout(repo.tags[tag.to_s].target.oid, :strategy => :force)
    cmd = "cloc --by-file --progress-rate=0 --quiet --json --skip-uniqueness ."
    puts "Done. Running `#{cmd}`..."
    Open3.popen3(cmd, :chdir=>"../httpd") do |stdin, stdout, stderr, wait_thr|
        results = JSON.parse(stdout.read)
        results["SUM"] = nil
        results["header"] = nil
        results.each do |key, data|
            # strip leading ./ from path
            path = key[2..-1]
            if data
                sloc = data["code"]
                if !should_ignore_file(path)
                    file = releases[tag].get_file(path)
                    file.sloc = sloc
                end
            end
        end
    end
    puts "Done."
end

oldbugs = {}

def matches(s, re)
    start_at = 0
    matches = []
    while(m = s.match(re, start_at))
        matches.push(m)
        yield m
        start_at = m.end(0)
    end
    matches
end

def contains_bug_references(bugs, c)
    results = {}
    git_svn_id_regexp = /^git-svn-id:/
    #Trim git-svn lines out of commit messages
    trimmed = c.message.lines.reject{|m| m.match(git_svn_id_regexp) }.join('\n')
    
    #FIRST - Look at the date, there are three ranges of interest - pre 2002, 2002, and 2002+
    if c.epoch_time < Time.new(2002, 3, 16, 0, 0, 0, "utc").to_i # Bug DB change happened midmarch
        # pre 2002 - old bug db, anywhere between 1 and 5 digit long numbers
        
        # I looked over all 1400 commit messages before 2.0, and this looks like it matches everything with no false positives - in fact, I couldn't find a link it didn't match
        trimmed.scan(/PR:?\s+(\d+)(,\s*(\d+)(\(\?\))?)*/i) do |str|
            # Strip potential leading PR:, then split the resulting comma seperated list
            str.slice! 'PR'
            str.slice! 'pr' # This may never actually occur in this time range
            str.slice! ':'
            str.split.each do |cap|
                num = cap.to_i # to_i is very flexible - it skips leading whitespace, and ignore trailing non-int characters
                if !num.nil?
                    if 1 <= num && num <= 10295
                        oldbugs[num] ||= Bug.fromGNATS(num)
                        results[oldbugs[num].uid] = oldbugs[num]
                    end
                end
            end
        end
    elsif c.epoch_time < Time.new(2003, 7, 16, 0, 0, 0, "utc").to_i # Give a ~4 month transition period
        # 2002 - new bug db is only values between 7180 and 10844 (values > 7180 are ambiguous as to which bug they mean)
        trimmed.scan(/PR:?\s+(\d+)(,\s*(\d+)(\(\?\))?)*/i) do |str|
            # Strip potential leading PR:, then split the resulting comma seperated list
            str.slice! 'PR'
            str.slice! 'pr' # this may never actually occur in this time range
            str.slice! ':'
            str.split.each do |cap|
                num = cap.to_i # to_i is very flexible - it skips leading whitespace, and ignore trailing non-int characters
                if !num.nil?
                    if 1 <= num && num < 7180
                        # has to be old bug db
                        oldbugs[num] ||= Bug.fromGNATS(num)
                        results[oldbugs[num].uid] = oldbugs[num]
                    elsif num > 10295
                        # must be new bug db
                        if bugs[num]
                            results[bugs[num].uid] = bugs[num]
                        end
                    else
                        sha = c.oid
                        if bugs[num]
                            puts "Ambiguous pr reference #{num} at commit sha #{sha}, assuming new bug db..."
                            results[bugs[num].uid] = bugs[num]
                        else
                            puts "Ambiguous pr reference #{num} at commit sha #{sha}, however new bug db has no entry for that - must be old bug db?"
                            oldbugs[num] ||= Bug.fromGNATS(num)
                            results[oldbugs[num].uid] = oldbugs[num]
                        end
                    end
                end
            end
        end
    else
        # 2002 onward - 4 (>7000) or 5 digit numbers in the new bug db - the same regex can be used, but the term `bz` comes into vogue later on
        # Additionally, many authors started omitting the space and colon between the abbreviation and the number
        trimmed.scan(/((PR|BZ):?\s+)(\d\d\d\d\d?)(,\s*(\d\d\d\d\d?)(\(\?\))?)*|(PR|BZ)(\d\d\d\d\d?)/i) do |str|
            str.slice! 'PR'
            str.slice! 'pr'
            str.slice! 'BZ'
            str.slice! 'bz'
            str.split.each do |cap|
                num = cap.to_i
                if !num.nil?
                    if bugs[num]
                        results[bugs[num].uid] = bugs[num]
                    end
                end
            end
        end
    end
    return results
end

def walk_repo_between(releases, bugs, start_tag, end_tag, should_churn)
    # We expect httpd to be checked out at ../httpd
    repo = Rugged::Repository.new('../httpd')

    releases[end_tag] ||= FileTable.new(end_tag)
    walker = Rugged::Walker.new(repo)
    walker.sorting(Rugged::SORT_TOPO | Rugged::SORT_REVERSE)
    walker.push(repo.tags[end_tag.to_s].target)
    if start_tag == :head
        walker.hide(repo.branches['trunk'].target)
    elsif start_tag == :tail
        walker.hide(repo.lookup('5dbf830701af760e37e1e2c26212c34220516d85')) # This is the httpd initial commit
    else
        walker.hide(repo.tags[start_tag.to_s].target)
    end
    count = 0
    $stdout.sync = true
    shas = []
    puts "Collecting bug data for #{end_tag}"
    walker.each do |c|
        count = count + 1
        # Print some status indicator dots
        if count % 100 == 0
            print "."
        end
        shas.push(c.oid)
        candidate_bugs = contains_bug_references(bugs, c)
        candidate_bugs.each do |uid, bug|
            update_file_bugs(releases[end_tag], bug, c)
        end 
    end
    puts ""
    walker.reset
    if should_churn
        count = 0
        puts "Collecting churn data for #{end_tag}"
        shas.each do |sha|
            count = count + 1
            # Print some status indicator dots
            if count % 100 == 0
                print "."
            end
            # Forcibly close the repo every so often to relieve memory pressure
            if count % 1000 == 0
                repo.close()
                repo = Rugged::Repository.new('../httpd');
            end
            update_file_churn(releases[end_tag], repo.lookup(sha))
        end
        puts ""
    end
end

# Generate bug data
count_sloc(releases, $FIRST_VERSION)
walk_repo_between(releases, bugs, :tail, $FIRST_VERSION, false)
count_sloc(releases, $SECOND_VERSION)
walk_repo_between(releases, bugs, $FIRST_VERSION, $SECOND_VERSION, false)
count_sloc(releases, $THIRD_VERSION)
walk_repo_between(releases, bugs, $SECOND_VERSION, $THIRD_VERSION, false)

repo = Rugged::Repository.new('../httpd');
# Add in the vulnerability data
vulnerabilities.each do |cve, vulnerability|
    vulnerability.fix_hashes.each do |sha|
        fix = repo.lookup(sha)
        if fix
            # Conceivably, this method of adding vulnerabilities could be bilked by a renamed file between versions which is vulnerable
            # Fixing that would require tracking down backport commits - likely by mining commit messages for CVE references again
            if vulnerability.versions_present.include?("2.0")
                update_file_vulnerabilities(releases[$FIRST_VERSION], fix);
            end
            if vulnerability.versions_present.include?("2.2")
                update_file_vulnerabilities(releases[$SECOND_VERSION], fix);
            end
            if vulnerability.versions_present.include?("2.4")
                update_file_vulnerabilities(releases[$THIRD_VERSION], fix);
            end
        end
    end
end

releases.each do |version, files|
    #write out CSV result
    CSV.open("./data/results-v#{version}.csv", "wb") do |csv|
        csv << [:filepath, :churn, :num_commits, :sloc, :bugs, :enhancements, :blocker_sev_bugs, :major_sev_bugs, :minor_sev_bugs, :critical_sev_bugs, :normal_sev_bugs, :trivial_sev_bugs, :regressions, :vulnerabilities]
        files.each do |file|
            csv << [file.filepath, file.churn, file.num_commits, file.sloc, file.bugs, file.enhancements, file.blocker_sev_bugs, file.major_sev_bugs, file.minor_sev_bugs, file.critical_sev_bugs, file.normal_sev_bugs, file.trivial_sev_bugs, file.regressions, file.vulnerabilities]
        end
    end
end