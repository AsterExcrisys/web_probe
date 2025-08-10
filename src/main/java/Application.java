import com.asterexcrisys.webprobe.commands.Root;
import com.asterexcrisys.webprobe.services.ExceptionHandler;
import picocli.CommandLine;
import picocli.CommandLine.ParseResult;
import java.util.Optional;

public class Application {

    public static void main(String[] arguments) {
        CommandLine command = new CommandLine(new Root());
        command.setExecutionExceptionHandler(new ExceptionHandler());
        command.setParameterExceptionHandler(new ExceptionHandler());
        int exitCode = command.execute(arguments);
        fetchResult(command).ifPresent(System.out::println);
        System.exit(exitCode);
    }

    private static Optional<String> fetchResult(CommandLine command) {
        if (command.getExecutionResult() != null) {
            return Optional.of(command.getExecutionResult());
        }
        ParseResult result = command.getParseResult();
        while (result.hasSubcommand()) {
            CommandLine subcommand = result.subcommand().commandSpec().commandLine();
            if (subcommand.getExecutionResult() != null) {
                return Optional.of(subcommand.getExecutionResult());
            }
            result = subcommand.getParseResult();
        }
        return Optional.empty();
    }

}