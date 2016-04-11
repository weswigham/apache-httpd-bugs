require './models/bug.rb'
require './models/release_file.rb'
require './models/vulnerability.rb'
require 'rugged'
require 'csv'
require 'open3'
require 'json'

#Load in bug data
bugs = {}
CSV.foreach("./data/bugs-2016-03-04.csv", headers: true) do |row|
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
                file.save
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
                    #file.sloc
                    file.save
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
                file.save
            end
        end
    end
end

def count_sloc(releases, tag)
    repo = Rugged::Repository.new('../httpd');
    releases[tag] ||= FileTable.new(tag)
    puts "Checking out tag #{tag} to calculate sloc..."
    repo.checkout(repo.tags[tag.to_s].target.oid)
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
                    file.save
                end
            end
        end
    end
    puts "Done."
end

def walk_repo_between(releases, bugs, start_tag, end_tag)
    # We expect httpd to be checked out at ../httpd
    repo = Rugged::Repository.new('../httpd')
    bugid_regexp = /\s+(\d\d\d\d\d?)|PR(\d\d\d\d\d?)|Fix(?:es)?(\d\d\d\d\d?)|Bug(\d\d\d\d\d?)/i
    git_svn_id_regexp = /^git-svn-id:/
    releases[end_tag] = FileTable.new(end_tag)
    walker = Rugged::Walker.new(repo)
    walker.sorting(Rugged::SORT_TOPO | Rugged::SORT_REVERSE)
    if start_tag == :head
        walker.push(repo.branches['trunk'].target)
    else
        walker.push(repo.tags[start_tag.to_s].target)
    end
    walker.hide(repo.tags[end_tag.to_s].target)
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
        #Trim git-svn lines out of commit messages
        trimmed = c.message.lines.reject{|m| m.match(git_svn_id_regexp) }.join('\n')
        #Then match against our bug id regex
        matches = trimmed.scan(bugid_regexp)
        if matches
            matches.each do |cap|
                cap.each do |num|
                    if !num.nil?
                        if bugs[num]
                            update_file_bugs(releases[end_tag], bugs[num], c)
                        end
                    end
                end
            end
        end 
    end
    puts ""
    walker.reset
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


# Generate bug data
count_sloc(releases, :"2.0.1")
walk_repo_between(releases, bugs, :"2.2.1", :"2.0.1")
count_sloc(releases, :"2.2.1")
walk_repo_between(releases, bugs, :"2.4.1", :"2.2.1")
count_sloc(releases, :"2.4.1")
walk_repo_between(releases, bugs, :head, :"2.4.1")

repo = Rugged::Repository.new('../httpd');
# Add in the vulnerability data
vulnerabilities.each do |cve, vulnerability|
    vulnerability.fix_hashes.each do |sha|
        fix = repo.lookup(sha)
        if fix
            # Conceivably, this method of adding vulnerabilities could be bilked by a renamed file between versions which is vulnerable
            # Fixing that would require tracking down backport commits - likely by mining commit messages for CVE references again
            if vulnerability.versions_present.include?("2.0")
                update_file_vulnerabilities(releases[:"2.0.1"], fix);
            end
            if vulnerability.versions_present.include?("2.2")
                update_file_vulnerabilities(releases[:"2.2.1"], fix);
            end
            if vulnerability.versions_present.include?("2.4")
                update_file_vulnerabilities(releases[:"2.4.1"], fix);
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