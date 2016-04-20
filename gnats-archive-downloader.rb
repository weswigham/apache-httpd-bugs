require 'open-uri'
require 'thread'
$stdout.sync = true
puts "Downloading 10295 bug reports to data/gnats_archive..."
work_q = Queue.new
(1..10295).to_a.each{|x| work_q.push x }
workers = (0...30).map do
  Thread.new do
    begin
      while i = work_q.pop(true)
        open("data/gnats_archive/#{i}.txt", 'wb') do |file|
            begin
                file << open("http://archive.apache.org/gnats/#{i}").read
            rescue OpenURI::HTTPError => e
                file << "--- Error ---"
                file << e.message
            end
            complete = 10295 - work_q.length
            print "\r#{complete}/10295"
        end
      end
    rescue ThreadError
    end
  end
end

workers.map(&:join)
puts ""