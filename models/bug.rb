class Bug
    attr_accessor :id, :component, :assignee, :status, :resolution, :summary, :changed, :priority, :severity, :reporter, :url, :version, :keywords
    
    def self.fromCSVRow(row)
        bug = self.new
        bug.id = row[0]
        #Skip product because it's always just apache httpd
        bug.component = row[2]
        bug.assignee = row[3]
        bug.status = row[4]
        bug.resolution = row[5]
        bug.summary = row[6]
        bug.changed = row[7]
        bug.priority = row[8]
        bug.severity = row[9]
        bug.reporter = row[10]
        bug.url = row[11]
        bug.version = row[12]
        bug.keywords = row[13]
        return bug
    end
end