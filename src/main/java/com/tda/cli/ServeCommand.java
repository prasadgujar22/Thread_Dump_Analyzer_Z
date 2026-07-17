package com.tda.cli;

import com.tda.web.TdaServer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

@Command(name = "serve", mixinStandardHelpOptions = true,
        description = "Start the local web UI (binds to localhost only unless --host says otherwise).")
public class ServeCommand implements Callable<Integer> {

    @Option(names = "--port", defaultValue = "8080",
            description = "Port to listen on (default: ${DEFAULT-VALUE}).")
    int port;

    @Option(names = "--host", defaultValue = "127.0.0.1",
            description = "Bind address. Keep the default: dumps are sensitive (default: ${DEFAULT-VALUE}).")
    String host;

    @Override
    public Integer call() throws Exception {
        TdaServer server = new TdaServer(host, port);
        server.start();
        System.out.printf("TDA web UI: http://%s:%d/  (Ctrl-C to stop; nothing leaves this machine)%n",
                host.equals("0.0.0.0") ? "localhost" : host, server.port());
        Thread.currentThread().join();
        return 0;
    }
}
