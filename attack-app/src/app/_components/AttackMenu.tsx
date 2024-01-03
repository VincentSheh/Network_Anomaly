import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

export default async function AttackMenu() {
  const handleAttack = async ()=>{

  }
  return (
    <Tabs defaultValue="attack" className="bg-white text-black rounded-log w-3/4">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="attack">Attack Choice</TabsTrigger>
        <TabsTrigger value="commandline">Command Line</TabsTrigger>
      </TabsList>
      <TabsContent value="attack">
        <Card>
          <CardHeader>
            <CardTitle>Start Attacking!</CardTitle>
            <CardDescription>
             Choose your attack parameters here
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
          <div className="flex flex-col space-y-1.5">
            <Label htmlFor="framework">Attack Type</Label>
              <Select>
                <SelectTrigger id="framework">
                  <SelectValue placeholder="Select" />
                </SelectTrigger>
                <SelectContent className="bg-white" position="popper">
                  <SelectItem value="dos">DoS</SelectItem>
                  <SelectItem value="goldeneye">DoS Goldeneye</SelectItem>
                  <SelectItem value="portscan">Portscan</SelectItem>
                  <SelectItem value="bruteforce">Bruteforce</SelectItem>
                </SelectContent>
              </Select>
          </div>
            <div className="space-y-1">
              <Label htmlFor="target">Target</Label>
              <Input id="target" defaultValue="127.0.0.1" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="port">Port</Label>
              <Input id="port" defaultValue="3000" />
            </div>            
          </CardContent>
          <CardFooter>
            <Button>Start Attacking</Button>
          </CardFooter>
        </Card>
      </TabsContent>
      <TabsContent value="commandline">
        <Card>
          <CardHeader>
            <CardTitle>Command Line</CardTitle>
            <CardDescription>
              Check the attacker's command line output
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="space-y-1">
              <Label htmlFor="current">Command Line</Label>
              <Input id="current" type="password" />
            </div>
          </CardContent>
          <CardFooter>
            <Button>Save password</Button>
          </CardFooter>
        </Card>
      </TabsContent>
    </Tabs>
  )
}
