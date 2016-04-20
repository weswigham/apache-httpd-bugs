class Bug
    attr_accessor :id, :product, :component, :assignee, :status, :resolution, :summary, :changed, :alias, :assignee_real_name, :hardware, :keywords, :num_comments, :opened, :os, :priority, :reporter, :reporter_real_name, :severity, :version, :target_milestone, :tags, :url
    
    def self.fromCSVRow(row)
        bug = self.new
        bug.id = row[0]
        bug.product = row[1]
        bug.component = row[2]
        bug.assignee = row[3]
        bug.status = row[4]
        bug.resolution = row[5]
        bug.summary = row[6]
        bug.changed = row[7]
        bug.alias = row[8]
        bug.assignee_real_name = row[9]
        bug.hardware = row[10]
        bug.keywords = row[11]
        bug.num_comments = row[12]
        bug.opened = row[13]
        bug.os = row[14]
        bug.priority = row[15]
        bug.reporter = row[16]
        bug.reporter_real_name = row[17]
        bug.severity = row[18]
        bug.version = row[19]
        bug.target_milestone = row[20]
        bug.tags = row[21]
        bug.url = row[22]
        return bug
    end
end