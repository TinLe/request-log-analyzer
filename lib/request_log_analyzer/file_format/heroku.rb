module RequestLogAnalyzer::FileFormat

  # Based on Default FileFormat class for Rails 3 logs.
  #
  # For now, this is just a basic implementation. It will probaby change after
  # Rails 3 final has been released.
  class Heroku < Base

    extend CommonRegularExpressions

    # beta4: Started GET "/" for 127.0.0.1 at Wed Jul 07 09:13:27 -0700 2010 (different time format)
    line_definition :started do |line|
      line.header = true
      line.teaser = /Started /
      line.regexp = /Started ([A-Z]+) "([^"]+)" for (#{ip_address}) at (#{timestamp('%a %b %d %H:%M:%S %z %Y')}|#{timestamp('%Y-%m-%d %H:%M:%S %z')})/
      
      line.capture(:method)
      line.capture(:path)
      line.capture(:ip)
      line.capture(:timestamp).as(:timestamp)
    end
    
    # Processing by QueriesController#index as HTML
    line_definition :processing do |line|
      line.teaser = /Processing by /
      line.regexp = /Processing by ([A-Za-z0-9\-:]+)\#(\w+) as ([\w\/\*]*)/
      
      line.capture(:controller)
      line.capture(:action)
      line.capture(:format)
    end

    # Parameters: {"action"=>"cached", "controller"=>"cached"}
    line_definition :parameters do |line|
      line.teaser = / Parameters:/
      line.regexp = / Parameters:\s+(\{.*\})/
      line.capture(:params).as(:eval)
    end
    
    # Heroku uses:
    # Mar 22 09:49:39 d.2bfca441-5ee3-4dc0-b44e-dfb93c223e58 app[web.4] Started POST "/4f43e9c3d9380800010 00007/4f6ae3a947f041000a000298" for 12.123.456.78 at 2012-03-22 09:49:39 +0000
    # Mar 22 09:49:39 d.2bfca441-5ee3-4dc0-b44e-dfb93c223e58 heroku[router] POST www.any.com/4f43e9c3d938080001000007/4f6ae3a947f041000a000298 dyno=web.4 queue=0 wait=0ms service=125ms status=302 bytes=141
    # Apr 18 22:20:03 d.2bfca441-5ee3-4dc0-b44e-dfb93c223e58 app[web.4] Started GET "/kkk-bbbbbbbbb/pregnancy-symptoms-including-the-ones?zXFj&utm_source=stumbleupon&utm_medium=cpc&utm_term=pregnancy&utm_content=sideeffects&utm_campaign=SU_PregSE&zQZj" for 12.123.456.789 at 2012-04-18 22:20:03 +0000
    # Apr 18 22:20:03 d.2bfca441-5ee3-4dc0-b44e-dfb93c223e58 app[web.4] cache: [GET /kkk-bbbbbbbbb/pregnancy-symptoms-including-the-ones?zXFj&utm_source=stumbleupon&utm_medium=cpc&utm_term=pregnancy&utm_content=sideeffects&utm_campaign=SU_PregSE&zQZj] miss
    # Apr 18 22:20:03 d.2bfca441-5ee3-4dc0-b44e-dfb93c223e58 heroku[router] GET www.any.com/kkk-bbbbbbbbb/pregnancy-symptoms-including-the-ones?zXFj&utm_source=stumbleupon&utm_medium=cpc&utm_term=pregnancy&utm_content=sideeffects&utm_campaign=SU_PregSE&zQZj dyno=web.4 queue=0 wait=0ms service=228ms status=301 bytes=139
    line_definition :completed do |line|
      line.footer = true
      line.teaser = /heroku\[router\] /
      # line.regexp = /heroku\[router\] ([A-Z]+) "[^"]+" dyno=web\.\d+ queue=\d+ wait=\d+ms service=(\d+)ms status=(\d+) bytes=\d+/
      line.regexp = /heroku\[router\] ([A-Z]+) ([^"]+) dyno=web\.\d+ queue=\d+ wait=(\d+)ms service=(\d+)ms status=(\d+) bytes=\d+/

      line.capture(:method)
      line.capture(:path)
      line.capture(:view).as(:duration, :unit => :msec)
      line.capture(:duration).as(:duration, :unit => :msec)
      line.capture(:status).as(:integer)
    end

    # ActionView::Template::Error (undefined local variable or method `field' for #<Class>) on line #3 of /Users/willem/Code/warehouse/app/views/queries/execute.csv.erb:
    line_definition :failure do |line|
      line.footer = true
      line.regexp = /((?:[A-Z]\w*[a-z]\w+\:\:)*[A-Z]\w*[a-z]\w+) \((.*)\)(?: on line #(\d+) of (.+))?\:\s*$/

      line.capture(:error)
      line.capture(:message)
      line.capture(:line).as(:integer)
      line.capture(:file)
    end
    
    # # Not parsed at the moment:
    # SQL (0.2ms) SET SQL_AUTO_IS_NULL=0
    # Query Load (0.4ms) SELECT `queries`.* FROM `queries`
    # Rendered collection (0.0ms)
    # Rendered queries/index.html.erb (0.6ms)
    
    REQUEST_CATEGORIZER = lambda { |request| "#{request[:controller]}##{request[:action]}.#{request[:format]}" }
    
    report do |analyze|
      
      analyze.timespan
      analyze.hourly_spread
      
      analyze.frequency :category => REQUEST_CATEGORIZER, :title => 'Most requested'
      analyze.frequency :method, :title => 'HTTP methods'
      analyze.frequency :status, :title => 'HTTP statuses returned'
      
      analyze.duration :duration, :category => REQUEST_CATEGORIZER, :title => "Request duration", :line_type => :completed
      analyze.duration :view, :category => REQUEST_CATEGORIZER, :title => "View rendering time", :line_type => :completed
      analyze.duration :db, :category => REQUEST_CATEGORIZER, :title => "Database time", :line_type => :completed
      
      analyze.frequency :category => REQUEST_CATEGORIZER, :title => 'Process blockers (> 1 sec duration)',
        :if => lambda { |request| request[:duration] && request[:duration] > 1.0 }
    end
    
    class Request < RequestLogAnalyzer::Request
      # Used to handle conversion of abbrev. month name to a digit
      MONTHS = %w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)
      
      def convert_timestamp(value, definition)
        # the time value can be in 2 formats:
        # - 2010-10-26 02:27:15 +0000 (ruby 1.9.2)
        # - Thu Oct 25 16:15:18 -0800 2010
        if value =~ /^#{CommonRegularExpressions::TIMESTAMP_PARTS['Y']}/
          value.gsub!(/\W/,'')
          value[0..13].to_i
        else
          value.gsub!(/\W/,'')
          time_as_str = value[-4..-1] # year
          # convert the month to a 2-digit representation
          month = MONTHS.index(value[3..5])+1
          month < 10 ? time_as_str << "0#{month}" : time_as_str << month.to_s

          time_as_str << value[6..13] # day of month + time
          time_as_str.to_i
        end

      end
    end

  end
end
