class Bug
    attr_accessor :uid, :is_old, :id, :product, :component, :assignee, :status, :resolution, :summary, :changed, :alias, :assignee_real_name, :hardware, :keywords, :num_comments, :opened, :os, :priority, :reporter, :reporter_real_name, :severity, :version, :target_milestone, :tags, :url
    @@uid = 0

    def self.fromCSVRow(row)
        @@uid = @@uid + 1
        bug = self.new
        bug.uid = @@uid
        bug.is_old = false
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
    
    def self.fromGNATS(id)
        @@uid = @@uid + 1
        bug = self.new
        bug.uid = @@uid
        bug.is_old = true
        bug.id = id

        File.new("./data/gnats_archive/#{id}.txt").each do |line|
            if line =~ /^>Arrival-Date:\s+(.*)$/i
                bug.opened = $1
            elsif line =~ /^>Severity:\s+(.*)$/i
                bug.severity = $1
            elsif line =~ /^>Priority:\s+(.*)$/i
                bug.priority = $1
            elsif line =~ /^>Category:\s+(.*)$/i
                bug.component = $1
            elsif line =~ /^>Release:\s+(.*)$/i
                bug.version = $1
            elsif line =~ /^>Synopsis:\s+(.*)$/i
                bug.summary = $1
            end
        end
        return bug
    end
end