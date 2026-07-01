public class App {
    void handle(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");

        Runtime.getRuntime().exec(request.getParameter("cmd"));
    }
}
